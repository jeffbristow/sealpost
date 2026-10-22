<?php
/* =====================================================================
 * Sealpost Sync Server — api.php
 * ---------------------------------------------------------------------
 * The address Sealpost talks to. Every request names an "action":
 *     https://your-site/…/api.php?action=pull
 * Requests and replies are JSON. Signed-in requests carry the device
 * token in the X-Sealpost-Token header.
 *
 * Sections (one per action):
 *   0. Startup, error handling, action router
 *   1. ping        — is this a Sealpost server? does a vault exist?
 *   2. prelogin    — key-derivation settings for a username
 *   3. setup       — create the vault (needs the setup code, once)
 *   4. login       — sign a device in
 *   5. logout      — sign this device out
 *   6. meta        — vault info for a signed-in device
 *   7. pull        — items changed since sequence number N
 *   8. push        — upload changed / deleted items (conflict-checked)
 *   9. devices     — list signed-in devices
 *  10. revoke      — sign another device out
 *  11. changeAuth  — new passphrase (re-wrapped vault key + login key)
 *  12. destroy     — delete the whole vault (needs the passphrase)
 *  13. pinSetup / pinUnlock / pinRemove / lock — PIN unlock for a phone or
 *      browser (1.5.0). How it stays safe:
 *        - the phone keeps your vault key encrypted with a key made from
 *          (your PIN + a random secret that only this server holds)
 *        - the server hands that secret out only after the right PIN
 *          proof, and forgets the phone after 5 wrong PINs
 *      So a stolen phone can't be brute-forced offline, and the server
 *      alone never has your vault key or PIN.
 * ===================================================================== */

declare(strict_types=1);
define('SEALPOST', 1);
require __DIR__ . '/lib.php';

/* =================================================================
 * 0. STARTUP, ERROR HANDLING, ACTION ROUTER
 * ================================================================= */
ini_set('display_errors', '0');
set_exception_handler(function (Throwable $e) {
    error_log('Sealpost sync: ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine());
    fail(500, 'server_error', 'The server had a problem with that request.');
});

require_secure_transport();

$action = (string) ($_GET['action'] ?? '');
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

// Only "ping" may be a simple GET; everything else must be a JSON POST
if ($action !== 'ping' && $method !== 'POST') {
    fail(405, 'post_only', 'Use POST for this request.');
}

$routes = [
    'ping'       => 'act_ping',
    'prelogin'   => 'act_prelogin',
    'setup'      => 'act_setup',
    'login'      => 'act_login',
    'logout'     => 'act_logout',
    'meta'       => 'act_meta',
    'pull'       => 'act_pull',
    'push'       => 'act_push',
    'devices'    => 'act_devices',
    'revoke'     => 'act_revoke',
    'changeAuth' => 'act_change_auth',
    'destroy'    => 'act_destroy',
    'pinSetup'   => 'act_pin_setup',
    'pinUnlock'  => 'act_pin_unlock',
    'pinRemove'  => 'act_pin_remove',
    'lock'       => 'act_lock',
];
if (!isset($routes[$action])) fail(404, 'unknown_action', 'Unknown request.');
$routes[$action]();

/* =================================================================
 * 1. PING
 *    Lets Sealpost confirm the address is right before asking for
 *    a passphrase, and tells it whether to offer "Create" or "Connect".
 * ================================================================= */
function act_ping(): void
{
    reply([
        'app'        => 'sealpost-sync',
        'api'        => SEALPOST_API_VERSION,
        'server'     => SEALPOST_SERVER_VERSION,
        'vault'      => vault_has_users(),
        'setupOpen'  => !vault_has_users() && trim((string) cfg('setup_code')) !== '',
        'https'      => is_https(),
        'time'       => time(),
    ]);
}

/* =================================================================
 * 2. PRELOGIN
 *    Returns how this username's passphrase is stretched. Unknown
 *    usernames get the default answer so this can't be used to find
 *    out which usernames exist.
 * ================================================================= */
function act_prelogin(): void
{
    $username = v_username(input('username'));
    $user = find_user($username);
    reply(['kdf' => $user ? json_decode($user['kdf'], true) : default_kdf()]);
}

/* =================================================================
 * 3. SETUP
 *    Creates the one vault this server holds. Requires the setup
 *    code from config.php and only works while no vault exists.
 *    The device that creates the vault is signed in right away.
 * ================================================================= */
function act_setup(): void
{
    $code = trim((string) cfg('setup_code'));
    if ($code === '') fail(403, 'setup_disabled', 'Creating a vault is switched off in config.php.');

    rl_check(['setup:' . client_ip() => 5]);
    $given = strtoupper(trim((string) input('setupCode', '')));
    if (!hash_equals(strtoupper($code), $given)) {
        rl_record(['setup:' . client_ip()]);
        fail(403, 'bad_setup_code', 'That setup code is not correct. It is in config.php on your server.');
    }

    $username   = v_username(input('username'));
    $authKey    = v_authkey(input('authKey'));
    $kdf        = v_kdf(input('kdf'));
    $wrappedKey = v_blob(input('wrappedKey'), 4096, 'wrappedKey');
    $device     = v_device_name(input('deviceName'));
    $kind       = v_kind(input('kind'));

    $pdo = db();
    $pdo->exec('BEGIN IMMEDIATE');
    try {
        if ((int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn() > 0) {
            $pdo->exec('ROLLBACK');
            fail(409, 'vault_exists', 'A vault already exists on this server. Use "Connect" instead.');
        }
        $pdo->prepare('INSERT INTO users (username, auth_hash, kdf, wrapped_key, key_version, seq, created) VALUES (?,?,?,?,1,0,?)')
            ->execute([$username, password_hash($authKey, hash_algo()), json_encode($kdf), $wrappedKey, time()]);
        $userId = (int) $pdo->lastInsertId();
        $dev = new_device($userId, $device, $kind);
        $pdo->exec('COMMIT');
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) $pdo->exec('ROLLBACK');
        throw $e;
    }
    rl_clear('setup:' . client_ip());
    reply($dev + ['username' => $username, 'keyVersion' => 1, 'seq' => 0]);
}

/* =================================================================
 * 4. LOGIN
 *    Device proves it knows the passphrase by sending the login key
 *    derived from it. Gets a device token + the wrapped vault key.
 * ================================================================= */
function act_login(): void
{
    $username = v_username(input('username'));
    $authKey  = v_authkey(input('authKey'));
    rl_check(login_buckets($username));

    $user = find_user($username);
    if (!$user) {
        rl_record(array_keys(login_buckets($username)));
        password_hash($authKey, hash_algo()); // takes as long as a real check, so timing reveals nothing
        usleep(random_int(150000, 400000));
        fail(401, 'bad_login', 'Wrong username or passphrase.');
    }
    if (!verify_login_key($user, $authKey)) fail(401, 'bad_login', 'Wrong username or passphrase.');

    // 1.5.0: a phone signing in again with the passphrase (after its PIN
    // was reset or skipped) replaces its own earlier registration
    $old = (string) input('replaceDevice', '');
    if (preg_match('/^[0-9a-f]{16}$/', $old)) {
        db()->prepare("DELETE FROM devices WHERE id = ? AND user_id = ? AND kind = 'web'")->execute([$old, $user['id']]);
    }
    $dev = new_device((int) $user['id'], v_device_name(input('deviceName')), v_kind(input('kind')));
    reply($dev + [
        'username'   => $user['username'],
        'wrappedKey' => $user['wrapped_key'],
        'kdf'        => json_decode($user['kdf'], true),
        'keyVersion' => (int) $user['key_version'],
        'seq'        => (int) $user['seq'],
    ]);
}

/* =================================================================
 * 5. LOGOUT — forget this device's token
 * ================================================================= */
function act_logout(): void
{
    $me = require_auth();
    db()->prepare('DELETE FROM devices WHERE id = ?')->execute([$me['device_id']]);
    reply();
}

/* =================================================================
 * 6. META
 *    keyVersion changes when the passphrase changes: a device that
 *    sees a new number knows it must ask for the new passphrase.
 * ================================================================= */
function act_meta(): void
{
    $me = require_auth();
    $count = db()->prepare('SELECT COUNT(*) FROM items WHERE user_id = ? AND deleted = 0');
    $count->execute([$me['id']]);
    reply([
        'username'   => $me['username'],
        'wrappedKey' => $me['wrapped_key'],
        'kdf'        => json_decode($me['kdf'], true),
        'keyVersion' => (int) $me['key_version'],
        'seq'        => (int) $me['seq'],
        'items'      => (int) $count->fetchColumn(),
        'deviceId'   => $me['device_id'],
        'deviceName' => $me['device_name'],
    ]);
}

/* =================================================================
 * 7. PULL
 *    Everything that changed after sequence number "since", oldest
 *    first, in pages. Deleted items come back with deleted:true so
 *    other devices delete them too.
 * ================================================================= */
function act_pull(): void
{
    $me = require_auth();
    $since = max(0, (int) input('since', 0));
    $limit = min(1000, max(1, (int) input('limit', 500)));

    $st = db()->prepare('SELECT item_id, seq, data, deleted, updated FROM items
                         WHERE user_id = ? AND seq > ? ORDER BY seq ASC LIMIT ' . ($limit + 1));
    $st->execute([$me['id'], $since]);
    $rows = $st->fetchAll();
    $more = count($rows) > $limit;
    if ($more) array_pop($rows);

    $items = array_map(fn($r) => [
        'id'      => $r['item_id'],
        'seq'     => (int) $r['seq'],
        'data'    => $r['deleted'] ? null : $r['data'],
        'deleted' => (bool) $r['deleted'],
        'updated' => (int) $r['updated'],
    ], $rows);

    reply([
        'items'      => $items,
        'more'       => $more,
        'seq'        => (int) $me['seq'],
        'keyVersion' => (int) $me['key_version'],
    ]);
}

/* =================================================================
 * 8. PUSH
 *    Each item says which version it was based on ("base" = the seq
 *    the device last saw for it, 0 for a new item). If someone else
 *    changed it in the meantime the server refuses that one item and
 *    sends back its copy, so the device can merge and try again.
 *    Nothing is ever overwritten blindly.
 * ================================================================= */
function act_push(): void
{
    $me = require_auth();
    $items = input('items');
    if (!is_array($items) || count($items) > 500) fail(400, 'bad_items', 'Send between 0 and 500 items at a time.');
    $expectKey = input('keyVersion');
    if ($expectKey !== null && (int) $expectKey !== (int) $me['key_version']) {
        fail(409, 'key_changed', 'The vault passphrase was changed on another device. Enter the new passphrase.');
    }

    $maxBytes = (int) cfg('max_item_kb') * 1024;
    // validate everything before touching the database
    $clean = [];
    foreach ($items as $it) {
        if (!is_array($it)) fail(400, 'bad_items', 'Invalid item.');
        $deleted = !empty($it['deleted']);
        $clean[] = [
            'id'      => v_item_id($it['id'] ?? ''),
            'base'    => max(0, (int) ($it['base'] ?? 0)),
            'deleted' => $deleted,
            'data'    => $deleted ? null : v_blob($it['data'] ?? '', $maxBytes),
        ];
    }

    $pdo = db();
    $results = [];
    $pdo->exec('BEGIN IMMEDIATE');
    try {
        $seq = (int) $pdo->query('SELECT seq FROM users WHERE id = ' . (int) $me['id'])->fetchColumn();
        $get = $pdo->prepare('SELECT seq, data, deleted, updated FROM items WHERE user_id = ? AND item_id = ?');
        $put = $pdo->prepare('INSERT INTO items (user_id, item_id, seq, data, deleted, updated, device_id) VALUES (?,?,?,?,?,?,?)
                              ON CONFLICT(user_id, item_id) DO UPDATE SET seq = excluded.seq, data = excluded.data,
                              deleted = excluded.deleted, updated = excluded.updated, device_id = excluded.device_id');
        $countLive = $pdo->prepare('SELECT COUNT(*) FROM items WHERE user_id = ? AND deleted = 0');
        $countLive->execute([$me['id']]);
        $live = (int) $countLive->fetchColumn();
        $maxItems = (int) cfg('max_items');

        foreach ($clean as $it) {
            $get->execute([$me['id'], $it['id']]);
            $cur = $get->fetch() ?: null;
            $curSeq = $cur ? (int) $cur['seq'] : 0;

            if ($it['base'] !== $curSeq) {
                // someone else changed it first — hand back the server's copy
                $results[] = ['id' => $it['id'], 'ok' => false, 'conflict' => true, 'server' => [
                    'id' => $it['id'], 'seq' => $curSeq,
                    'data' => $cur && !$cur['deleted'] ? $cur['data'] : null,
                    'deleted' => $cur ? (bool) $cur['deleted'] : true,
                    'updated' => $cur ? (int) $cur['updated'] : 0,
                ]];
                continue;
            }
            if ($it['deleted'] && (!$cur || $cur['deleted'])) {
                $results[] = ['id' => $it['id'], 'ok' => true, 'seq' => $curSeq]; // already gone
                continue;
            }
            if (!$it['deleted'] && (!$cur || $cur['deleted'])) {
                if ($live >= $maxItems) {
                    $results[] = ['id' => $it['id'], 'ok' => false, 'error' => 'vault_full'];
                    continue;
                }
                $live++;
            } elseif ($it['deleted']) {
                $live--;
            }
            $seq++;
            $put->execute([$me['id'], $it['id'], $seq, $it['data'], $it['deleted'] ? 1 : 0, time(), $me['device_id']]);
            $results[] = ['id' => $it['id'], 'ok' => true, 'seq' => $seq];
        }
        $pdo->prepare('UPDATE users SET seq = ? WHERE id = ?')->execute([$seq, $me['id']]);
        $pdo->exec('COMMIT');
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) $pdo->exec('ROLLBACK');
        throw $e;
    }
    reply(['results' => $results, 'seq' => $seq]);
}

/* =================================================================
 * 9. DEVICES
 * ================================================================= */
function act_devices(): void
{
    $me = require_auth();
    $st = db()->prepare('SELECT id, name, kind, created, last_seen FROM devices WHERE user_id = ? ORDER BY last_seen DESC');
    $st->execute([$me['id']]);
    $list = array_map(fn($d) => [
        'id' => $d['id'], 'name' => $d['name'], 'kind' => $d['kind'],
        'created' => (int) $d['created'], 'lastSeen' => (int) $d['last_seen'],
        'current' => $d['id'] === $me['device_id'],
    ], $st->fetchAll());
    reply(['devices' => $list]);
}

/* =================================================================
 * 10. REVOKE — sign another device out (it must sign in again)
 * ================================================================= */
function act_revoke(): void
{
    $me = require_auth();
    $id = (string) input('id', '');
    if (!preg_match('/^[0-9a-f]{16}$/', $id)) fail(400, 'bad_id', 'Invalid device.');
    $st = db()->prepare('DELETE FROM devices WHERE id = ? AND user_id = ?');
    $st->execute([$id, $me['id']]);
    reply(['removed' => $st->rowCount() > 0]);
}

/* =================================================================
 * 11. CHANGE AUTH — new vault passphrase
 *    The vault key itself stays the same (so nothing has to be
 *    re-encrypted); it is just wrapped again with the new passphrase.
 *    Requires the current login key as proof.
 * ================================================================= */
function act_change_auth(): void
{
    $me = require_auth();
    rl_check(login_buckets($me['username']));
    $oldKey = v_authkey(input('authKey'));
    if (!verify_login_key($me, $oldKey)) fail(401, 'bad_login', 'The current passphrase is not correct.');

    $newKey     = v_authkey(input('newAuthKey'), 'newAuthKey');
    $kdf        = v_kdf(input('kdf'));
    $wrappedKey = v_blob(input('wrappedKey'), 4096, 'wrappedKey');
    $signOutOthers = !empty(input('signOutOthers'));

    $pdo = db();
    $pdo->prepare('UPDATE users SET auth_hash = ?, kdf = ?, wrapped_key = ?, key_version = key_version + 1 WHERE id = ?')
        ->execute([password_hash($newKey, hash_algo()), json_encode($kdf), $wrappedKey, $me['id']]);
    if ($signOutOthers) {
        $pdo->prepare('DELETE FROM devices WHERE user_id = ? AND id <> ?')->execute([$me['id'], $me['device_id']]);
    }
    reply(['keyVersion' => (int) $me['key_version'] + 1]);
}

/* =================================================================
 * 12. DESTROY — delete the vault, its items and all devices
 *    Afterwards a new vault can be created with the setup code.
 * ================================================================= */
function act_destroy(): void
{
    $me = require_auth();
    rl_check(login_buckets($me['username']));
    if (!verify_login_key($me, v_authkey(input('authKey')))) fail(401, 'bad_login', 'The passphrase is not correct.');
    $pdo = db();
    $pdo->exec('BEGIN IMMEDIATE');
    $pdo->prepare('DELETE FROM items WHERE user_id = ?')->execute([$me['id']]);
    $pdo->prepare('DELETE FROM devices WHERE user_id = ?')->execute([$me['id']]);
    $pdo->prepare('DELETE FROM users WHERE id = ?')->execute([$me['id']]);
    $pdo->exec('COMMIT');
    $pdo->exec('VACUUM');
    reply();
}

/* =================================================================
 * 13. PIN UNLOCK (1.5.0)
 * ================================================================= */

/** { pinAuth } — this signed-in device gets PIN unlock. -> { secret, deviceId } */
function act_pin_setup(): void
{
    $me = require_auth();
    $pinAuth = v_authkey(input('pinAuth'), 'pinAuth');
    $secret = bin2hex(random_bytes(32));
    db()->prepare('UPDATE devices SET pin_hash = ?, unlock_secret = ?, pin_fails = 0 WHERE id = ?')
        ->execute([password_hash($pinAuth, hash_algo()), $secret, $me['device_id']]);
    reply(['secret' => $secret, 'deviceId' => $me['device_id']]);
}

/**
 * { deviceId, pinAuth } -> { token, secret, username, keyVersion, deviceName }
 * No token needed (the app is locked); the PIN proof is the key.
 */
function act_pin_unlock(): void
{
    $deviceId = (string) input('deviceId', '');
    if (!preg_match('/^[0-9a-f]{16}$/', $deviceId)) fail(400, 'bad_id', 'Invalid device.');
    $pinAuth = v_authkey(input('pinAuth'), 'pinAuth');
    rl_check(['pinip:' . client_ip() => 30]);

    $pdo = db();
    $st = $pdo->prepare('SELECT d.*, u.username, u.key_version FROM devices d JOIN users u ON u.id = d.user_id WHERE d.id = ?');
    $st->execute([$deviceId]);
    $d = $st->fetch();
    if (!$d || !$d['pin_hash']) fail(401, 'pin_reset', 'PIN unlock is no longer set up on this device. Sign in with your vault passphrase.');
    if (time() - (int) $d['last_seen'] > PIN_DEVICE_IDLE) {
        $pdo->prepare('DELETE FROM devices WHERE id = ?')->execute([$deviceId]);
        fail(401, 'pin_reset', 'This device wasn\'t used for 30 days. Sign in with your vault passphrase.');
    }
    if (!password_verify($pinAuth, $d['pin_hash'])) {
        rl_record(['pinip:' . client_ip()]);
        $fails = (int) $d['pin_fails'] + 1;
        if ($fails >= PIN_MAX_FAILS) {
            $pdo->prepare('DELETE FROM devices WHERE id = ?')->execute([$deviceId]);
            fail(401, 'pin_reset', 'Too many wrong PINs. Sign in with your vault passphrase.');
        }
        $pdo->prepare('UPDATE devices SET pin_fails = ? WHERE id = ?')->execute([$fails, $deviceId]);
        usleep(random_int(200000, 500000));
        $left = PIN_MAX_FAILS - $fails;
        fail(401, 'bad_pin', "Wrong PIN. $left " . ($left === 1 ? 'try' : 'tries') . ' left.', ['triesLeft' => $left]);
    }
    // right PIN: a fresh session token for this device
    $token = bin2hex(random_bytes(32));
    $pdo->prepare('UPDATE devices SET token_hash = ?, pin_fails = 0, last_seen = ?, last_ip = ? WHERE id = ?')
        ->execute([hash('sha256', $token), time(), client_ip(), $deviceId]);
    reply(['token' => $token, 'secret' => $d['unlock_secret'], 'username' => $d['username'], 'keyVersion' => (int) $d['key_version'], 'deviceName' => $d['name']]);
}

/** Turn PIN unlock off for this device (signing out of it does this too). */
function act_pin_remove(): void
{
    $me = require_auth();
    db()->prepare('UPDATE devices SET pin_hash = NULL, unlock_secret = NULL, pin_fails = 0 WHERE id = ?')->execute([$me['device_id']]);
    reply();
}

/**
 * Lock (PIN devices): the session token stops working, but the device
 * stays registered so the PIN can open it again.
 */
function act_lock(): void
{
    $me = require_auth();
    db()->prepare('UPDATE devices SET token_hash = ? WHERE id = ?')->execute([hash('sha256', bin2hex(random_bytes(32))), $me['device_id']]);
    reply();
}
