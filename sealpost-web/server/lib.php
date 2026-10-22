<?php
/* =====================================================================
 * Sealpost Sync Server — lib.php
 * ---------------------------------------------------------------------
 * Shared building blocks used by api.php (and index.php):
 * configuration, the vault database, input checks, rate limiting and
 * device tokens.
 *
 * ZERO-KNOWLEDGE NOTE
 *   Nothing in this server can read your data. Sealpost encrypts every
 *   item (accounts, contacts, keys, settings) on your PC with a vault
 *   key that only exists on your devices. The server stores:
 *     - your username
 *     - an Argon2id hash of a LOGIN KEY derived from your passphrase
 *       (the passphrase itself never leaves your PC)
 *     - the vault key, wrapped (encrypted) with another key derived
 *       from your passphrase
 *     - encrypted items + their sync sequence numbers
 *     - device names and hashed device tokens
 *
 * Sections:
 *   1. Bootstrap + configuration
 *   2. JSON replies
 *   3. Request reading (method, body, HTTPS)
 *   4. Vault database (SQLite, created automatically)
 *   5. Input validation
 *   6. Rate limiting (failed logins)
 *   7. Device tokens (sign-in sessions)
 *   (3b. raw message uploads with X-Sealpost-Meta — 1.2.0)
 * ===================================================================== */

declare(strict_types=1);

if (!defined('SEALPOST')) {
    http_response_code(404);
    exit;
}

/* =================================================================
 * 1. BOOTSTRAP + CONFIGURATION
 * ================================================================= */
const SEALPOST_API_VERSION = 1;
const SEALPOST_SERVER_VERSION = '1.9.2';
const WEB_SESSION_IDLE = 12 * 3600;   // seconds a web sign-in stays valid without use
const PIN_DEVICE_IDLE = 30 * 86400;   // a phone / browser with PIN unlock is forgotten after 30 days unused (1.5.0)
const PIN_MAX_FAILS = 5;              // wrong PINs before the device must sign in with the vault passphrase again

/** Settings from config.php merged over safe defaults. */
function cfg(?string $key = null)
{
    static $cfg = null;
    if ($cfg === null) {
        $defaults = [
            'setup_code' => '',
            'data_dir' => '',
            'require_https' => true,
            'login_failures_per_user' => 5,
            'login_failures_per_ip' => 20,
            'lockout_minutes' => 15,
            'max_item_kb' => 1024,
            'max_items' => 20000,
            'max_request_mb' => 16,
        ];
        $file = __DIR__ . '/config.php';
        $loaded = is_file($file) ? require $file : [];
        $cfg = array_merge($defaults, is_array($loaded) ? $loaded : []);
    }
    return $key === null ? $cfg : ($cfg[$key] ?? null);
}

/** Folder holding vault.sqlite — outside the public web folder by default. */
function data_dir(): string
{
    $dir = trim((string) cfg('data_dir'));
    if ($dir === '') {
        $docRoot = rtrim((string) ($_SERVER['DOCUMENT_ROOT'] ?? ''), '/');
        $base = $docRoot !== '' ? dirname($docRoot) : dirname(__DIR__, 2);
        $dir = $base . '/sealpost-data';
    }
    return rtrim($dir, '/');
}

/* =================================================================
 * 2. JSON REPLIES
 *    Success: {"ok":true, ...}
 *    Failure: {"ok":false, "error":"code", "message":"Readable text"}
 * ================================================================= */
function send_json(array $payload, int $status = 200): void
{
    if (!headers_sent()) {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store, max-age=0');
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: no-referrer');
        header('X-Robots-Tag: noindex, nofollow');
    }
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function reply(array $data = []): void
{
    send_json(['ok' => true] + $data);
}

function fail(int $status, string $code, string $message, array $extra = []): void
{
    send_json(['ok' => false, 'error' => $code, 'message' => $message] + $extra, $status);
}

/* =================================================================
 * 3. REQUEST READING
 * ================================================================= */
function client_ip(): string
{
    // REMOTE_ADDR only: forwarded-for headers can be faked by anyone
    return (string) ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
}

function is_localhost(): bool
{
    return in_array(client_ip(), ['127.0.0.1', '::1'], true);
}

function is_https(): bool
{
    if (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off') return true;
    if ((string) ($_SERVER['SERVER_PORT'] ?? '') === '443') return true;
    if (strtolower((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https') return true;
    if (strtolower((string) ($_SERVER['REQUEST_SCHEME'] ?? '')) === 'https') return true;
    return false;
}

/** Stop unless the request came over HTTPS (or from the server itself). */
function require_secure_transport(): void
{
    if (cfg('require_https') && !is_https() && !is_localhost()) {
        fail(403, 'https_required', 'This server only accepts secure (https://) connections.');
    }
}

/** JSON body of a POST request as an array (size-limited). */
function read_body(): array
{
    static $body = null;
    if ($body !== null) return $body;
    $max = (int) cfg('max_request_mb') * 1048576;
    $len = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
    if ($len > $max) fail(413, 'too_large', 'That upload is too large for this server.');
    $raw = file_get_contents('php://input', false, null, 0, $max + 1);
    if ($raw === false) $raw = '';
    if (strlen($raw) > $max) fail(413, 'too_large', 'That upload is too large for this server.');
    if ($raw === '') return $body = [];
    $data = json_decode($raw, true);
    if (!is_array($data)) fail(400, 'bad_json', 'The request could not be read.');
    return $body = $data;
}

/**
 * Raw request body (a finished email from Sealpost Web) plus the JSON
 * details that travel with it in the X-Sealpost-Meta header (base64).
 * Used for sending and saving drafts, so big attachments aren't
 * inflated by JSON encoding. (1.2.0)
 */
function read_raw_with_meta(int $maxBytes): array
{
    $len = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
    if ($len > $maxBytes) fail(413, 'too_large', 'This message is larger than this server allows (' . (int) ($maxBytes / 1048576) . ' MB).');
    $raw = file_get_contents('php://input', false, null, 0, $maxBytes + 1);
    if ($raw === false || $raw === '') fail(400, 'empty', 'The message is empty.');
    if (strlen($raw) > $maxBytes) fail(413, 'too_large', 'This message is larger than this server allows.');
    $meta = json_decode(base64_decode((string) ($_SERVER['HTTP_X_SEALPOST_META'] ?? ''), true) ?: '', true);
    if (!is_array($meta)) fail(400, 'bad_meta', 'Missing message details.');
    return [$raw, $meta];
}

/** One field from the JSON body (or the query string for GET). */
function input(string $name, $default = null)
{
    $body = read_body();
    if (array_key_exists($name, $body)) return $body[$name];
    if (isset($_GET[$name])) return $_GET[$name];
    return $default;
}

/* =================================================================
 * 4. VAULT DATABASE
 *    One SQLite file. Created with its folder on first use.
 *
 *    users    one row per vault owner
 *    devices  one row per signed-in Sealpost / browser
 *    items    encrypted items; seq rises with every change so devices
 *             can ask "what changed since N?"
 *    attempts failed sign-ins (for rate limiting)
 * ================================================================= */
function db(): PDO
{
    static $pdo = null;
    if ($pdo) return $pdo;

    $dir = data_dir();
    if (!is_dir($dir)) {
        if (!@mkdir($dir, 0700, true) && !is_dir($dir)) {
            fail(500, 'storage', 'The vault folder could not be created. Check data_dir in config.php.');
        }
    }
    // belt and braces in case the folder ends up inside the website
    if (!is_file($dir . '/.htaccess')) {
        @file_put_contents($dir . '/.htaccess', "Require all denied\nDeny from all\n");
    }
    if (!is_file($dir . '/index.html')) @file_put_contents($dir . '/index.html', '');

    $file = $dir . '/vault.sqlite';
    $isNew = !is_file($file);
    try {
        $pdo = new PDO('sqlite:' . $file, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
    } catch (Throwable $e) {
        fail(500, 'storage', 'The vault database could not be opened.');
    }
    if ($isNew) @chmod($file, 0600);
    $pdo->exec('PRAGMA busy_timeout = 8000');
    $pdo->exec('PRAGMA foreign_keys = ON');
    $pdo->exec('PRAGMA journal_mode = WAL');

    $pdo->exec('CREATE TABLE IF NOT EXISTS users (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT NOT NULL UNIQUE,
        auth_hash   TEXT NOT NULL,
        kdf         TEXT NOT NULL,
        wrapped_key TEXT NOT NULL,
        key_version INTEGER NOT NULL DEFAULT 1,
        seq         INTEGER NOT NULL DEFAULT 0,
        created     INTEGER NOT NULL
    )');
    $pdo->exec('CREATE TABLE IF NOT EXISTS devices (
        id          TEXT PRIMARY KEY,
        user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name        TEXT NOT NULL,
        kind        TEXT NOT NULL,
        token_hash  TEXT NOT NULL UNIQUE,
        created     INTEGER NOT NULL,
        last_seen   INTEGER NOT NULL,
        last_ip     TEXT
    )');
    $pdo->exec('CREATE TABLE IF NOT EXISTS items (
        user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        item_id     TEXT NOT NULL,
        seq         INTEGER NOT NULL,
        data        TEXT,
        deleted     INTEGER NOT NULL DEFAULT 0,
        updated     INTEGER NOT NULL,
        device_id   TEXT,
        PRIMARY KEY (user_id, item_id)
    )');
    $pdo->exec('CREATE INDEX IF NOT EXISTS items_by_seq ON items(user_id, seq)');
    $pdo->exec('CREATE TABLE IF NOT EXISTS attempts (
        bucket TEXT NOT NULL,
        at     INTEGER NOT NULL
    )');
    $pdo->exec('CREATE INDEX IF NOT EXISTS attempts_by_bucket ON attempts(bucket, at)');
    // 1.5.0: PIN unlock for phones / browsers (columns added to older databases)
    $cols = array_column($pdo->query('PRAGMA table_info(devices)')->fetchAll(), 'name');
    if (!in_array('pin_hash', $cols, true)) {
        $pdo->exec('ALTER TABLE devices ADD COLUMN pin_hash TEXT');
        $pdo->exec('ALTER TABLE devices ADD COLUMN unlock_secret TEXT');
        $pdo->exec('ALTER TABLE devices ADD COLUMN pin_fails INTEGER NOT NULL DEFAULT 0');
    }
    return $pdo;
}

function vault_has_users(): bool
{
    return (int) db()->query('SELECT COUNT(*) FROM users')->fetchColumn() > 0;
}

function find_user(string $username): ?array
{
    $st = db()->prepare('SELECT * FROM users WHERE username = ?');
    $st->execute([$username]);
    $u = $st->fetch();
    return $u ?: null;
}

/* =================================================================
 * 5. INPUT VALIDATION
 *    Everything from the network is checked before it is used.
 * ================================================================= */
function v_username($v): string
{
    $u = strtolower(trim((string) $v));
    if (!preg_match('/^[a-z0-9._@+-]{3,64}$/', $u)) {
        fail(400, 'bad_username', 'Usernames are 3–64 characters: letters, numbers and . _ @ + -');
    }
    return $u;
}

/** Login key: 32 bytes as 64 hex characters, derived from the passphrase on the device. */
function v_authkey($v, string $field = 'authKey'): string
{
    $k = strtolower((string) $v);
    if (!preg_match('/^[0-9a-f]{64}$/', $k)) fail(400, 'bad_' . $field, 'Invalid login key.');
    return $k;
}

/** Key-derivation settings the devices use to turn the passphrase into keys. */
function v_kdf($v): array
{
    if (!is_array($v)) fail(400, 'bad_kdf', 'Invalid key-derivation settings.');
    $alg = (string) ($v['alg'] ?? '');
    $iter = (int) ($v['iter'] ?? 0);
    if ($alg !== 'pbkdf2-sha256' || $iter < 100000 || $iter > 10000000) {
        fail(400, 'bad_kdf', 'Invalid key-derivation settings.');
    }
    return ['alg' => $alg, 'iter' => $iter];
}

function default_kdf(): array
{
    return ['alg' => 'pbkdf2-sha256', 'iter' => 600000];
}

/** Encrypted blob produced by Sealpost: "v1." + base64. */
function v_blob($v, int $maxBytes, string $field = 'data'): string
{
    $s = (string) $v;
    if (strlen($s) > $maxBytes) fail(413, 'too_large', 'An item is larger than this server allows (' . $field . ').');
    if (!preg_match('#^v1\.[A-Za-z0-9+/]+=*$#', $s)) fail(400, 'bad_' . $field, 'Invalid encrypted data.');
    return $s;
}

/** Item ids look like "contact:2f1e…", "key:ABCD…", "settings:main". */
function v_item_id($v): string
{
    $s = (string) $v;
    if (!preg_match('/^[a-z]{2,20}:[A-Za-z0-9._@+-]{1,200}$/', $s)) fail(400, 'bad_item_id', 'Invalid item id.');
    return $s;
}

function v_device_name($v): string
{
    $s = preg_replace('/[\x00-\x1F\x7F]/u', '', trim((string) $v)) ?? '';
    if ($s === '') $s = 'Unnamed device';
    return mb_substr($s, 0, 64);
}

function v_kind($v): string
{
    return in_array($v, ['app', 'web'], true) ? $v : 'app';
}

/* =================================================================
 * 6. RATE LIMITING
 *    Each wrong passphrase is written down for the username and for
 *    the internet address it came from. Too many inside the lockout
 *    window and that username / address must wait.
 * ================================================================= */
function rl_window(): int
{
    return max(1, (int) cfg('lockout_minutes')) * 60;
}

/** Stop with HTTP 429 if any bucket is over its limit. $buckets = [name => limit]. */
function rl_check(array $buckets): void
{
    $now = time();
    $pdo = db();
    $pdo->prepare('DELETE FROM attempts WHERE at < ?')->execute([$now - rl_window()]);
    foreach ($buckets as $bucket => $limit) {
        $st = $pdo->prepare('SELECT COUNT(*) AS n, MIN(at) AS first FROM attempts WHERE bucket = ?');
        $st->execute([$bucket]);
        $row = $st->fetch();
        if ((int) $row['n'] >= $limit) {
            $wait = max(60, ((int) $row['first'] + rl_window()) - $now);
            fail(429, 'rate_limited', 'Too many wrong attempts. Try again in ' . (int) ceil($wait / 60) . ' minute(s).', ['retryAfter' => $wait]);
        }
    }
}

function rl_record(array $bucketNames): void
{
    $st = db()->prepare('INSERT INTO attempts (bucket, at) VALUES (?, ?)');
    foreach ($bucketNames as $b) $st->execute([$b, time()]);
}

function rl_clear(string $bucket): void
{
    db()->prepare('DELETE FROM attempts WHERE bucket = ?')->execute([$bucket]);
}

/** The usual pair of buckets for a sign-in attempt. */
function login_buckets(string $username): array
{
    return [
        'user:' . $username => max(1, (int) cfg('login_failures_per_user')),
        'ip:' . client_ip()  => max(1, (int) cfg('login_failures_per_ip')),
    ];
}

/** Check a login key against the stored hash; records failures. */
function verify_login_key(array $user, string $authKey): bool
{
    $ok = password_verify($authKey, $user['auth_hash']);
    if (!$ok) {
        rl_record(array_keys(login_buckets($user['username'])));
        usleep(random_int(150000, 400000)); // slows down guessing a little more
        return false;
    }
    rl_clear('user:' . $user['username']);
    if (password_needs_rehash($user['auth_hash'], hash_algo())) {
        db()->prepare('UPDATE users SET auth_hash = ? WHERE id = ?')->execute([password_hash($authKey, hash_algo()), $user['id']]);
    }
    return true;
}

function hash_algo()
{
    return defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
}

/* =================================================================
 * 7. DEVICE TOKENS
 *    Signing in gives the device a random 256-bit token. Only its
 *    SHA-256 is stored, so a copy of the database can't be used to
 *    sign in. Sealpost sends the token in the X-Sealpost-Token header.
 * ================================================================= */
function new_device(int $userId, string $name, string $kind): array
{
    $token = bin2hex(random_bytes(32));
    $id = bin2hex(random_bytes(8));
    $now = time();
    db()->prepare('INSERT INTO devices (id, user_id, name, kind, token_hash, created, last_seen, last_ip) VALUES (?,?,?,?,?,?,?,?)')
        ->execute([$id, $userId, $name, $kind, hash('sha256', $token), $now, $now, client_ip()]);
    return ['token' => $token, 'deviceId' => $id];
}

function request_token(): string
{
    $t = (string) ($_SERVER['HTTP_X_SEALPOST_TOKEN'] ?? '');
    if ($t === '') {
        $auth = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
        if (stripos($auth, 'Bearer ') === 0) $t = trim(substr($auth, 7));
    }
    return preg_match('/^[0-9a-f]{64}$/', $t) ? $t : '';
}

/** The signed-in user + device for this request, or HTTP 401. */
function require_auth(): array
{
    $token = request_token();
    if ($token === '') fail(401, 'not_signed_in', 'Not signed in.');
    $st = db()->prepare('SELECT d.id AS device_id, d.name AS device_name, d.kind AS device_kind, d.last_seen, d.pin_hash AS device_pin, u.*
                         FROM devices d JOIN users u ON u.id = d.user_id WHERE d.token_hash = ?');
    $st->execute([hash('sha256', $token)]);
    $row = $st->fetch();
    if (!$row) fail(401, 'not_signed_in', 'This device was signed out. Sign in again.');
    // Sealpost Web sessions end after 12 hours without use (1.1.0).
    // With PIN unlock (1.5.0) only the session ends; the device stays
    // registered (for 30 days without use) so the PIN can open it again.
    $idle = time() - (int) $row['last_seen'];
    if ($row['device_kind'] === 'web' && $idle > WEB_SESSION_IDLE) {
        if ($row['device_pin'] && $idle <= PIN_DEVICE_IDLE) {
            db()->prepare('UPDATE devices SET token_hash = ? WHERE id = ?')->execute([hash('sha256', bin2hex(random_bytes(32))), $row['device_id']]);
            fail(401, 'not_signed_in', 'Sealpost was locked. Enter your PIN.');
        }
        db()->prepare('DELETE FROM devices WHERE id = ?')->execute([$row['device_id']]);
        fail(401, 'not_signed_in', 'Your web session ended. Sign in again.');
    }
    // remember when the device was last seen (at most once a minute)
    if (time() - (int) $row['last_seen'] > 60) {
        db()->prepare('UPDATE devices SET last_seen = ?, last_ip = ? WHERE id = ?')->execute([time(), client_ip(), $row['device_id']]);
    }
    return $row;
}
