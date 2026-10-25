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
 *   8. Updates: check GitHub, install a signed package, undo (1.10.0)
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
const SEALPOST_SERVER_VERSION = '1.10.1';
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

/* =================================================================
 * 8. UPDATES (1.10.0)
 * -----------------------------------------------------------------
 * Where: server-update.json in the public GitHub repository
 * jeffbristow/sealpost: { version, url, sha256, size, note }.
 * Before anything is installed:
 *   - <url>.sig must be signed with Sealpost's update key (only the
 *     PUBLIC key is here — it can check signatures, not make them),
 *   - the downloaded file's SHA-256 must match the signed one,
 *   - the zip must be one "sealpost-server/" folder with ordinary file
 *     names, and its lib.php must say that version.
 * Never touched: config.php, the vault folder, files that aren't in the
 * package. Replaced files are kept in <vault folder>/server-backup/ so
 * "Undo" can put them back. Checked at most every 12 hours by itself.
 * ================================================================= */
const UPDATE_SOURCES = ['https://raw.githubusercontent.com/jeffbristow/sealpost/main/server-update.json'];
const UPDATE_PUBKEY = 'zXSxXU2KZXvLRhfUPhBqrnhkj+Foo8P+LfK1vEXxSUk=';   // Ed25519, base64
const UPDATE_EVERY = 12 * 3600;
const UPDATE_MAX_ZIP = 40 * 1048576;
const UPDATE_TOP = 'sealpost-server/';

/* ---------- 8a. small helpers ---------- */
/** The addresses to ask (config.php 'update_urls' can replace them). */
function up_sources(): array
{
    $own = cfg('update_urls');
    $list = (is_array($own) && $own) ? $own : UPDATE_SOURCES;
    return array_values(array_filter(array_map('strval', $list), 'up_url_ok'));
}

/** https:// only — plain http:// just to this machine itself (tests). */
function up_url_ok(string $url): bool
{
    return (bool) preg_match('~^(https://|http://(127\.0\.0\.1|localhost)[:/])~i', $url);
}

function up_signed_text(string $version, string $sha256): string
{
    return 'sealpost-server-update-v1|' . $version . '|' . strtolower($sha256);
}

/** Folder for update work + the backup (inside the vault folder, outside the website). */
function up_dir(string $sub = ''): string
{
    $d = data_dir() . '/server-update' . ($sub !== '' ? '/' . $sub : '');
    if (!is_dir($d)) @mkdir($d, 0700, true);
    return $d;
}

function up_read(string $name, array $default = []): array
{
    $j = json_decode((string) @file_get_contents(up_dir() . '/' . $name), true);
    return is_array($j) ? $j : $default;
}

function up_write(string $name, array $data): void
{
    @file_put_contents(up_dir() . '/' . $name, json_encode($data, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT), LOCK_EX);
}

function up_rm_tree(string $dir): void
{
    if (!is_dir($dir)) return;
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST) as $f) {
        $f->isDir() ? @rmdir($f->getPathname()) : @unlink($f->getPathname());
    }
    @rmdir($dir);
}

/** The reason PHP gave for the last failed file operation, if any. */
function up_why(): string
{
    $e = error_get_last();
    return $e ? '(' . preg_replace('/^\w+\(\S*\): /', '', (string) $e['message']) . ')' : '';
}

function up_opcache_forget(array $rels): void
{
    if (!function_exists('opcache_invalidate')) return;
    foreach ($rels as $rel) if (str_ends_with($rel, '.php')) @opcache_invalidate(__DIR__ . '/' . $rel, true);
}

/** Never replaced by an update: config.php, and the vault folder if it was put inside this one. */
function up_keep(string $rel): bool
{
    if ($rel === 'config.php') return true;
    $data = str_replace('\\', '/', (string) realpath(data_dir()));
    $here = str_replace('\\', '/', (string) realpath(__DIR__));
    if ($data !== '' && $here !== '' && str_starts_with($data . '/', $here . '/')) {
        $inside = ltrim(substr($data, strlen($here)), '/');
        if ($inside !== '' && ($rel === $inside || str_starts_with($rel, $inside . '/'))) return true;
    }
    return false;
}

function up_rel_ok(string $rel): bool
{
    return (bool) preg_match('~^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$~', $rel) && !preg_match('~(^|/)\.\.?(/|$)~', $rel);
}

/**
 * HTTPS GET with limits (follows GitHub's download redirects, https only).
 * $toFile: stream into that file instead of memory.
 * Returns ['ok', 'status', 'body', 'error'].
 */
function up_http_get(string $url, int $maxBytes, int $timeout = 20, ?string $toFile = null): array
{
    if (!up_url_ok($url)) return ['ok' => false, 'status' => 0, 'body' => '', 'error' => 'only https:// addresses'];
    if (!function_exists('curl_init')) return ['ok' => false, 'status' => 0, 'body' => '', 'error' => 'PHP "curl" is not available on this hosting'];
    $body = '';
    $got = 0;
    $fh = $toFile !== null ? @fopen($toFile, 'wb') : null;
    if ($toFile !== null && !$fh) return ['ok' => false, 'status' => 0, 'body' => '', 'error' => 'cannot write ' . basename($toFile)];
    $local = !str_starts_with(strtolower($url), 'https://');
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_FOLLOWLOCATION => !$local,
        CURLOPT_MAXREDIRS => 5,
        CURLOPT_PROTOCOLS => $local ? CURLPROTO_HTTP : CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_USERAGENT => 'SealpostServer/' . SEALPOST_SERVER_VERSION,
        CURLOPT_WRITEFUNCTION => function ($ch, $chunk) use (&$body, &$got, $maxBytes, $fh) {
            $got += strlen($chunk);
            if ($got > $maxBytes) return 0;          // stop: too big
            if ($fh) fwrite($fh, $chunk); else $body .= $chunk;
            return strlen($chunk);
        },
    ]);
    $ok = curl_exec($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $err = $ok === false ? curl_error($ch) : '';
    curl_close($ch);
    if ($fh) fclose($fh);
    if ($got > $maxBytes) $err = 'the file is bigger than expected';
    elseif ($ok !== false && ($status < 200 || $status >= 300)) $err = 'HTTP ' . $status;
    return ['ok' => $err === '', 'status' => $status, 'body' => $body, 'error' => $err];
}

/** Ask one address; the cleaned { version, url, sha256, size, note } or null (+ $why). */
function up_ask(string $src, ?string &$why = null): ?array
{
    $r = up_http_get($src, 65536, 15);
    if (!$r['ok']) { $why = $r['error']; return null; }
    $j = json_decode($r['body'], true);
    $ver = is_array($j) ? (string) ($j['version'] ?? '') : '';
    $url = is_array($j) ? (string) ($j['url'] ?? '') : '';
    if (!preg_match('/^\d+\.\d+\.\d+$/', $ver) || !preg_match('~^\S+$~', $url) || !up_url_ok($url)) { $why = 'unreadable answer'; return null; }
    $sha = strtolower((string) ($j['sha256'] ?? ''));
    return ['version' => $ver, 'url' => $url, 'sha256' => preg_match('/^[a-f0-9]{64}$/', $sha) ? $sha : '',
            'size' => mb_substr((string) ($j['size'] ?? ''), 0, 20), 'note' => mb_substr((string) ($j['note'] ?? ''), 0, 300)];
}

/* ---------- 8b. check ---------- */
/** The newest version known: { checked, latest|null, error } (asked again after 12 h, or now with $force). */
function up_check(bool $force = false): array
{
    $c = up_read('check.json');
    if (!$force && !empty($c['checked']) && time() - (int) $c['checked'] < UPDATE_EVERY) return $c;
    $out = ['checked' => time(), 'latest' => null, 'error' => ''];
    $errors = [];
    foreach (up_sources() as $src) {
        $why = '';
        if ($w = up_ask($src, $why)) { $out['latest'] = $w; break; }
        $errors[] = parse_url($src, PHP_URL_HOST) . ': ' . $why;
    }
    if (!$out['latest']) {
        $out['error'] = implode(' · ', $errors);
        if (!empty($c['latest'])) $out['latest'] = $c['latest'];   // keep what we knew before
    }
    up_write('check.json', $out);
    return $out;
}

/** The version installed right now — read from lib.php on disk, so it's right even in the request that just updated (or undid) it. */
function up_current(): string
{
    clearstatcache(true, __DIR__ . '/lib.php');
    return preg_match("/SEALPOST_SERVER_VERSION = '([0-9.]+)'/", (string) @file_get_contents(__DIR__ . '/lib.php'), $m) ? $m[1] : SEALPOST_SERVER_VERSION;
}

/** The newer version's details, or null when this is the newest. */
function up_available(?array $c = null): ?array
{
    $c = $c ?? up_read('check.json');
    $l = $c['latest'] ?? null;
    return (is_array($l) && version_compare((string) $l['version'], up_current(), '>')) ? $l : null;
}

/** What would stop an update here (PHP can't write, missing extensions). Empty = fine. */
function up_blockers(): array
{
    $bad = [];
    if (!is_writable(__DIR__)) $bad[] = 'the Sealpost folder (' . basename(__DIR__) . '/) is not writable by PHP';
    foreach (['index.php', 'lib.php', 'api.php', 'web'] as $f) {
        if (file_exists(__DIR__ . '/' . $f) && !is_writable(__DIR__ . '/' . $f)) $bad[] = $f . ' is not writable by PHP';
    }
    if (!function_exists('sodium_crypto_sign_verify_detached')) $bad[] = 'PHP "sodium" (needed to check signatures) is not available';
    if (!class_exists('ZipArchive')) $bad[] = 'PHP "zip" is not available';
    if (!function_exists('curl_init')) $bad[] = 'PHP "curl" is not available';
    return $bad;
}

/** Everything the update screen shows. */
function up_state(?array $c = null): array
{
    $c = $c ?? up_read('check.json');
    $n = up_available($c);
    $b = up_backup();
    return [
        'current' => up_current(),
        'checked' => (int) ($c['checked'] ?? 0),
        'latest' => $c['latest']['version'] ?? null,
        'update' => $n ? ['version' => $n['version'], 'size' => $n['size'], 'note' => $n['note']] : null,
        'error' => (!empty($c['error']) && empty($c['latest'])) ? (string) $c['error'] : '',
        'blockers' => up_blockers(),
        'undo' => $b ? $b['version'] : null,
    ];
}

/* ---------- 8c. install ---------- */
/** Downloads, checks and installs the newer version. Returns [ok, message]. */
function up_install(): array
{
    if ($bad = up_blockers()) return [false, 'Can\'t update here: ' . implode('; ', $bad) . '.'];
    $work = up_dir('work');
    $lock = @fopen($work . '/.lock', 'c');
    if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) return [false, 'An update is already running — try again in a minute.'];
    @set_time_limit(300);
    try {
        $c = up_check(true);
        $want = up_available($c);
        if (!$want) return [false, ($c['error'] && empty($c['latest'])) ? 'Couldn\'t check for updates: ' . $c['error'] : 'Sealpost Server ' . SEALPOST_SERVER_VERSION . ' is already the newest.'];
        $ver = $want['version'];

        // 1. download the package and its signature
        $zip = $work . '/package.zip';
        @unlink($zip);
        $s = up_http_get($want['url'] . '.sig', 65536, 20);
        if (!$s['ok']) return [false, 'Couldn\'t download the update\'s signature: ' . $s['error']];
        $z = up_http_get($want['url'], UPDATE_MAX_ZIP, 240, $zip);
        if (!$z['ok']) { @unlink($zip); return [false, 'Couldn\'t download the update: ' . $z['error']]; }
        $sig = json_decode($s['body'], true);

        // 2. signature + checksum
        $sha = hash_file('sha256', $zip);
        if (!is_array($sig) || ($sig['version'] ?? '') !== $ver || !is_string($sig['sig'] ?? null)) { @unlink($zip); return [false, 'Refused: the signature file is not for version ' . $ver . '. Nothing was changed.']; }
        if (!hash_equals(strtolower((string) ($sig['sha256'] ?? '')), $sha)) { @unlink($zip); return [false, 'Refused: the downloaded file does not match its signature (damaged or changed). Nothing was changed.']; }
        if ($want['sha256'] !== '' && !hash_equals($want['sha256'], $sha)) { @unlink($zip); return [false, 'Refused: the downloaded file does not match the published checksum. Nothing was changed.']; }
        $raw = base64_decode($sig['sig'], true);
        if ($raw === false || strlen($raw) !== SODIUM_CRYPTO_SIGN_BYTES
            || !sodium_crypto_sign_verify_detached($raw, up_signed_text($ver, $sha), base64_decode(UPDATE_PUBKEY))) {
            @unlink($zip);
            return [false, 'Refused: the update is NOT signed by Sealpost. Nothing was changed.'];
        }

        // 3. list the zip's files (nothing written into the site yet)
        $za = new ZipArchive();
        if ($za->open($zip) !== true) return [false, 'Refused: the package is not a readable zip.'];
        if ($za->numFiles > 2000) { $za->close(); return [false, 'Refused: too many files in the package.']; }
        $files = [];
        $total = 0;
        for ($i = 0; $i < $za->numFiles; $i++) {
            $st = $za->statIndex($i);
            $name = (string) $st['name'];
            if (!str_starts_with($name, UPDATE_TOP)) { $za->close(); return [false, 'Refused: unexpected file in the package (' . $name . ').']; }
            $rel = substr($name, strlen(UPDATE_TOP));
            if ($rel === '' || str_ends_with($rel, '/')) continue;    // folders
            if (!up_rel_ok($rel)) { $za->close(); return [false, 'Refused: unsafe file name in the package (' . $rel . ').']; }
            $total += (int) $st['size'];
            if ($total > 3 * UPDATE_MAX_ZIP) { $za->close(); return [false, 'Refused: the package unpacks too big.']; }
            if (up_keep($rel)) continue;
            $files[$rel] = $i;
        }
        $libInside = isset($files['lib.php']) ? (string) $za->getFromIndex($files['lib.php']) : '';
        if (!preg_match("/SEALPOST_SERVER_VERSION\\s*=\\s*'" . preg_quote($ver, '/') . "'/", $libInside) || !isset($files['index.php'], $files['api.php'])) {
            $za->close();
            return [false, 'Refused: the package is not Sealpost Server ' . $ver . '.'];
        }

        // 4. unpack into the vault folder first (outside the website); only new or changed files
        $stage = $work . '/stage';
        up_rm_tree($stage);
        @mkdir($stage, 0700, true);
        $changed = [];
        foreach ($files as $rel => $i) {
            $data = $za->getFromIndex($i);
            if ($data === false) { $za->close(); return [false, 'Couldn\'t read ' . $rel . ' from the package — nothing was changed.']; }
            $dst = __DIR__ . '/' . $rel;
            if (is_file($dst) && hash_file('sha256', $dst) === hash('sha256', $data)) continue;   // already the same
            $st = $stage . '/' . $rel;
            if (!is_dir(dirname($st))) @mkdir(dirname($st), 0700, true);
            if (@file_put_contents($st, $data) === false) { $za->close(); return [false, 'Couldn\'t unpack ' . $rel . ' — nothing was changed. ' . up_why()]; }
            $changed[] = $rel;
        }
        $za->close();

        // 5. back up what will be replaced (one backup: the version before this update)
        $bk = up_dir() . '/backup';
        up_rm_tree($bk);
        @mkdir($bk . '/files', 0700, true);
        $replaced = [];
        $added = [];
        foreach ($changed as $rel) {
            $dst = __DIR__ . '/' . $rel;
            if (is_file($dst)) {
                if (!is_dir(dirname($bk . '/files/' . $rel))) @mkdir(dirname($bk . '/files/' . $rel), 0700, true);
                if (!@copy($dst, $bk . '/files/' . $rel)) return [false, 'Couldn\'t back up ' . $rel . ' — nothing was changed. ' . up_why()];
                $replaced[] = $rel;
            } else {
                $added[] = $rel;
            }
        }
        up_write('backup.json', ['version' => SEALPOST_SERVER_VERSION, 'to' => $ver, 'made' => date('c'), 'replaced' => $replaced, 'added' => $added]);

        // 6. put each file in place: a copy next to it, then a swap (or straight over it)
        $done = [];
        $fail = null;
        foreach ($changed as $rel) {
            $dst = __DIR__ . '/' . $rel;
            if (!is_dir(dirname($dst)) && !@mkdir(dirname($dst), 0755, true)) { $fail = [$rel, up_why()]; break; }
            $tmp = $dst . '.sp-new';
            $ok = @copy($stage . '/' . $rel, $tmp) && @chmod($tmp, 0644) && @rename($tmp, $dst);
            if (!$ok) {
                $why = up_why();
                @unlink($tmp);
                if (!@copy($stage . '/' . $rel, $dst)) { $fail = [$rel, $why]; break; }
            }
            $done[] = $rel;
        }
        if ($fail) {
            up_restore();                                 // put back what was already replaced
            up_rm_tree($stage);
            return [false, 'Couldn\'t write ' . $fail[0] . ' — the previous version was kept. ' . $fail[1]
                . ' If no reason is given, your host\'s security scanner (e.g. Imunify360 in cPanel) may be blocking PHP from writing files: check its log, or upload the new zip by hand (keep your config.php).'];
        }
        up_rm_tree($stage);
        @unlink($zip);
        up_opcache_forget($done);
        return [true, 'Sealpost Server was updated from ' . SEALPOST_SERVER_VERSION . ' to ' . $ver . '. Your config.php and vault were kept.'];
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

/* ---------- 8d. undo ---------- */
/** The backup's details, or null when there is nothing to undo. */
function up_backup(): ?array
{
    $b = up_read('backup.json');
    return !empty($b['version']) ? $b : null;
}

/** Puts the files from before the last update back. Returns [ok, message]. */
function up_restore(): array
{
    $b = up_backup();
    if (!$b) return [false, 'There is no earlier version to go back to.'];
    $bk = up_dir() . '/backup/files/';
    $fails = [];
    foreach ((array) $b['replaced'] as $rel) {
        $rel = (string) $rel;
        if (!up_rel_ok($rel) || up_keep($rel)) continue;
        $dst = __DIR__ . '/' . $rel;
        if (!(@copy($bk . $rel, $dst . '.sp-old') && @rename($dst . '.sp-old', $dst)) && !@copy($bk . $rel, $dst)) $fails[] = $rel;
    }
    foreach ((array) $b['added'] as $rel) {
        $rel = (string) $rel;
        if (up_rel_ok($rel) && !up_keep($rel)) @unlink(__DIR__ . '/' . $rel);
    }
    up_opcache_forget((array) $b['replaced']);
    if ($fails) return [false, 'Some files couldn\'t be put back: ' . implode(', ', $fails)];
    up_rm_tree(up_dir() . '/backup');
    @unlink(up_dir() . '/backup.json');
    @unlink(up_dir() . '/check.json');                    // check again with the old version
    return [true, 'Sealpost Server is back to version ' . $b['version'] . '.'];
}
