<?php
/* =====================================================================
 * Sealpost Web — server readiness check   (sealpost-check.php)
 * ---------------------------------------------------------------------
 * Upload this ONE file anywhere on your website, open it in a browser
 * with the access key, and it reports whether this hosting account can
 * run the Sealpost web interface.
 *
 *   https://your-site.example/sealpost-check.php?key=ACCESS_KEY
 *   (add &format=json for a machine-readable report)
 *
 * It does NOT change anything on the server. It creates one temporary
 * test folder (and removes it again) to check file permissions.
 * When you're done, use the "Delete this file" button at the bottom,
 * or delete it yourself — it reveals details about your server.
 *
 * Sections:
 *   0. Settings + access protection
 *   1. Helpers (result recording, network probe)
 *   2. PHP version + extensions
 *   3. Limits (memory, uploads, time)
 *   4. Disabled functions / network functions
 *   5. Files: writable storage, protected folder test
 *   6. HTTPS + sessions + crypto
 *   7. Outbound connections to mail servers + key servers
 *   8. Verdict
 *   9. Output (HTML page or JSON)
 * ===================================================================== */

/* =====================================================================
 * 0. SETTINGS + ACCESS PROTECTION
 * ===================================================================== */
const ACCESS_KEY = 'c7f00d43103bfb6744f9338d';   // must be given as ?key=...

if (!isset($_GET['key']) || !hash_equals(ACCESS_KEY, (string)$_GET['key'])) {
    http_response_code(404);                       // look like nothing is here
    exit;
}
header('X-Robots-Tag: noindex, nofollow');
header('Cache-Control: no-store');
@set_time_limit(90);

// --- Self-delete (button at the bottom of the report) ---
if (isset($_POST['delete_self']) && hash_equals(ACCESS_KEY, (string)($_POST['key'] ?? ''))) {
    $ok = @unlink(__FILE__);
    header('Content-Type: text/plain; charset=utf-8');
    echo $ok ? "sealpost-check.php has been deleted from the server." : "Could not delete the file — please delete sealpost-check.php with your file manager / FTP.";
    exit;
}

// Mail servers to test. Your own mail host can be typed in on the page (?imap=…&smtp=…).
$siteHost = preg_replace('/:\d+$/', '', $_SERVER['HTTP_HOST'] ?? 'localhost');
$siteHost = preg_replace('/^www\./i', '', $siteHost);
$imapHost = trim($_GET['imap'] ?? ('mail.' . $siteHost));
$smtpHost = trim($_GET['smtp'] ?? ('mail.' . $siteHost));
$validHost = fn($h) => (bool)preg_match('/^[a-z0-9.-]{1,253}$/i', $h);
if (!$validHost($imapHost)) $imapHost = 'mail.' . $siteHost;
if (!$validHost($smtpHost)) $smtpHost = 'mail.' . $siteHost;

/* =====================================================================
 * 1. HELPERS
 * ===================================================================== */
$results = [];   // each: [section, name, status(pass|warn|fail|info), value, note]

function add($section, $name, $status, $value, $note = '') {
    global $results;
    $results[] = compact('section', 'name', 'status', 'value', 'note');
}

/** Convert php.ini sizes like "128M" to bytes (-1 = unlimited). */
function toBytes($v) {
    $v = trim((string)$v);
    if ($v === '' ) return 0;
    if ($v === '-1') return -1;
    $n = (float)$v;
    switch (strtolower(substr($v, -1))) {
        case 'g': $n *= 1024;
        case 'm': $n *= 1024;
        case 'k': $n *= 1024;
    }
    return (int)$n;
}
function fmtBytes($b) {
    if ($b < 0) return 'unlimited';
    if ($b >= 1073741824) return round($b / 1073741824, 1) . ' GB';
    if ($b >= 1048576) return round($b / 1048576) . ' MB';
    return round($b / 1024) . ' KB';
}

/**
 * Try to reach host:port from this server.
 *   $mode 'tls'      = encrypted from the start (IMAPS 993, SMTPS 465, HTTPS 443)
 *   $mode 'plain'    = plain TCP, read the greeting (SMTP 587 / IMAP 143 before STARTTLS)
 * Returns [ok(bool), message, milliseconds]
 */
function probe($host, $port, $mode) {
    if (!function_exists('stream_socket_client')) return [false, 'stream_socket_client() is disabled', 0];
    $ctx = stream_context_create(['ssl' => [
        'verify_peer' => true, 'verify_peer_name' => true, 'SNI_enabled' => true, 'peer_name' => $host,
    ]]);
    $scheme = $mode === 'tls' ? 'ssl' : 'tcp';
    $t0 = microtime(true);
    $errno = 0; $errstr = '';
    $fp = @stream_socket_client("$scheme://$host:$port", $errno, $errstr, 8, STREAM_CLIENT_CONNECT, $ctx);
    $ms = (int)round((microtime(true) - $t0) * 1000);
    if (!$fp) {
        $why = $errstr ?: 'connection failed';
        if (stripos($why, 'certificate') !== false) $why = 'TLS certificate problem: ' . $why;
        return [false, $why, $ms];
    }
    stream_set_timeout($fp, 6);
    $greeting = '';
    if ($port != 443) $greeting = trim((string)fgets($fp, 512));
    fclose($fp);
    if ($port == 443) return [true, 'connected (TLS OK)', $ms];
    if ($greeting === '') return [true, 'connected, but no greeting received', $ms];
    return [true, 'connected — server says: ' . mb_strimwidth($greeting, 0, 90, '…'), $ms];
}

/* =====================================================================
 * 2. PHP VERSION + EXTENSIONS
 * ===================================================================== */
$ver = PHP_VERSION;
if (version_compare($ver, '8.1.0', '>=')) add('PHP', 'PHP version', 'pass', $ver, '8.1 or newer is needed.');
elseif (version_compare($ver, '7.4.0', '>=')) add('PHP', 'PHP version', 'fail', $ver, 'Too old. Ask your host (or use its control panel "PHP Selector") to switch this site to PHP 8.1 or newer.');
else add('PHP', 'PHP version', 'fail', $ver, 'Far too old — PHP 8.1+ required.');

add('PHP', 'Server software', 'info', ($_SERVER['SERVER_SOFTWARE'] ?? 'unknown') . ' · ' . PHP_SAPI . ' · ' . PHP_OS_FAMILY);

// [extension, required?, why]
$exts = [
    ['openssl',  true,  'Encrypted connections to your mail server (IMAPS/SMTPS) and HTTPS.'],
    ['mbstring', true,  'Correct handling of international text in email.'],
    ['iconv',    true,  'Converting email character sets.'],
    ['json',     true,  'Talking to the browser.'],
    ['ctype',    true,  'Basic text checks used by the mail library.'],
    ['fileinfo', true,  'Detecting attachment types.'],
    ['session',  true,  'Keeping you logged in.'],
    ['curl',     false, 'Looking up public keys online (keys.openpgp.org). Can fall back to streams.'],
    ['sodium',   false, 'Extra crypto helpers (password hashing / tokens).'],
    ['pdo_sqlite', false, 'Simplest storage for the encrypted sync vault (no database setup needed).'],
    ['pdo_mysql',  false, 'Alternative storage if SQLite is missing.'],
    ['dom',      false, 'Cleaning up HTML email.'],
    ['zip',      false, 'Downloading several attachments at once.'],
    ['imap',     false, 'Not needed — Sealpost Web uses a pure-PHP mail library (the imap extension was removed from PHP 8.4).'],
    ['gnupg',    false, 'Not needed and NOT used — all PGP happens in your browser so keys never live on the server.'],
];
foreach ($exts as [$e, $req, $why]) {
    $has = extension_loaded($e);
    if ($e === 'imap' || $e === 'gnupg') { add('Extensions', $e, 'info', $has ? 'present' : 'not present', $why); continue; }
    add('Extensions', $e, $has ? 'pass' : ($req ? 'fail' : 'warn'), $has ? 'loaded' : 'missing', $why);
}
if (!extension_loaded('pdo_sqlite') && !extension_loaded('pdo_mysql')) {
    add('Extensions', 'Storage', 'fail', 'none', 'Neither SQLite nor MySQL PDO is available — the sync vault needs one of them.');
}

/* =====================================================================
 * 3. LIMITS
 * ===================================================================== */
$mem = toBytes(ini_get('memory_limit'));
add('Limits', 'memory_limit', ($mem < 0 || $mem >= 128 * 1048576) ? 'pass' : ($mem >= 64 * 1048576 ? 'warn' : 'fail'), fmtBytes($mem),
    '128 MB+ recommended (large attachments are processed in memory).');

$up = toBytes(ini_get('upload_max_filesize'));
$post = toBytes(ini_get('post_max_size'));
$eff = ($post < 0) ? $up : min($up < 0 ? PHP_INT_MAX : $up, $post);
add('Limits', 'Largest upload (attachments, backup import)', $eff >= 25 * 1048576 ? 'pass' : ($eff >= 8 * 1048576 ? 'warn' : 'fail'),
    fmtBytes($eff) . " (upload_max_filesize " . ini_get('upload_max_filesize') . ", post_max_size " . ini_get('post_max_size') . ")",
    '25 MB+ recommended so attachments of normal size can be sent.');

$met = (int)ini_get('max_execution_time');
add('Limits', 'max_execution_time', ($met === 0 || $met >= 60) ? 'pass' : ($met >= 30 ? 'warn' : 'fail'), $met === 0 ? 'unlimited' : $met . ' s',
    '60 s+ recommended (opening a large mailbox or sending a big attachment).');

$stl = function_exists('set_time_limit') && !in_array('set_time_limit', array_map('trim', explode(',', (string)ini_get('disable_functions'))));
add('Limits', 'set_time_limit() allowed', $stl ? 'pass' : 'warn', $stl ? 'yes' : 'no', 'Lets long operations extend their own time limit.');
add('Limits', 'max_file_uploads', (int)ini_get('max_file_uploads') >= 10 ? 'pass' : 'warn', ini_get('max_file_uploads'), 'Attachments per message.');

/* =====================================================================
 * 4. DISABLED FUNCTIONS / NETWORK FUNCTIONS
 * ===================================================================== */
$disabled = array_filter(array_map('trim', explode(',', (string)ini_get('disable_functions'))));
foreach (['stream_socket_client' => 'Connecting to your mail server', 'stream_socket_enable_crypto' => 'Upgrading SMTP/IMAP connections to TLS (STARTTLS)', 'fsockopen' => 'Fallback for mail connections', 'random_bytes' => 'Secure random tokens'] as $fn => $why) {
    $ok = function_exists($fn) && !in_array($fn, $disabled);
    add('Functions', $fn . '()', $ok ? 'pass' : ($fn === 'fsockopen' ? 'warn' : 'fail'), $ok ? 'available' : 'disabled', $why);
}
add('Functions', 'exec / proc_open', 'info', (function_exists('proc_open') && !in_array('proc_open', $disabled)) ? 'available' : 'disabled', 'Not needed — fine either way.');
add('Functions', 'open_basedir', 'info', ini_get('open_basedir') ?: 'not set', 'Limits which folders PHP may use; checked below.');

/* =====================================================================
 * 5. FILES: storage location + protected folder test
 * ===================================================================== */
$here = __DIR__;
$docRoot = rtrim(realpath($_SERVER['DOCUMENT_ROOT'] ?? $here) ?: $here, '/\\');
$aboveRoot = dirname($docRoot);

// Best: a data folder OUTSIDE the public web folder (cannot be downloaded at all).
$outsideOk = @is_writable($aboveRoot);
if ($outsideOk) {
    $probeDir = $aboveRoot . '/sealpost_probe_' . bin2hex(random_bytes(4));
    $outsideOk = @mkdir($probeDir, 0700) && @file_put_contents("$probeDir/t", 'x') === 1;
    @unlink("$probeDir/t"); @rmdir($probeDir);
}
add('Storage', 'Writable folder outside the public web folder', $outsideOk ? 'pass' : 'warn', $outsideOk ? $aboveRoot : 'not available',
    $outsideOk ? 'Ideal place for the encrypted sync vault — it can never be downloaded.' : 'The vault would live in a protected folder inside the website instead (see next check).');

// Inside the web folder: create a test folder with .htaccess "deny" and see if the web server really blocks it.
$testDir = $here . '/sealpost_protect_test_' . bin2hex(random_bytes(4));
$protectStatus = 'warn'; $protectValue = 'not tested'; $protectNote = '';
if (@mkdir($testDir, 0755)) {
    @file_put_contents("$testDir/.htaccess", "Require all denied\nDeny from all\n");
    @file_put_contents("$testDir/secret.txt", 'SEALPOST-SECRET-PROBE');
    add('Storage', 'Can create files in this folder', 'pass', 'yes', '');
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $url = $scheme . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\\') . '/' . basename($testDir) . '/secret.txt';
    $body = null; $code = 0;
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 8, CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => 0, CURLOPT_FOLLOWLOCATION => false]);
        $body = curl_exec($ch); $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
    } elseif (ini_get('allow_url_fopen')) {
        $body = @file_get_contents($url, false, stream_context_create(['http' => ['ignore_errors' => true, 'timeout' => 8], 'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]]));
        $code = isset($http_response_header[0]) && preg_match('/\s(\d{3})\s/', $http_response_header[0], $m) ? (int)$m[1] : 0;
    }
    if ($code === 0) { $protectValue = 'could not test (server cannot request its own address)'; $protectNote = 'Not a problem if the folder outside the web root (above) is writable.'; }
    elseif (is_string($body) && strpos($body, 'SEALPOST-SECRET-PROBE') !== false) { $protectStatus = 'fail'; $protectValue = "readable from the web (HTTP $code)"; $protectNote = '.htaccess rules are ignored here, so data must be stored outside the web folder.'; }
    else { $protectStatus = 'pass'; $protectValue = "blocked (HTTP $code)"; $protectNote = 'The web server honours .htaccess — a protected data folder inside the site works.'; }
    @unlink("$testDir/secret.txt"); @unlink("$testDir/.htaccess"); @rmdir($testDir);
} else {
    add('Storage', 'Can create files in this folder', 'fail', 'no', 'PHP cannot write here. Check folder permissions (755) or ask your host.');
}
add('Storage', 'Protected folder (.htaccess) really blocks downloads', $protectStatus, $protectValue, $protectNote);

$free = @disk_free_space($here);
add('Storage', 'Free disk space', $free === false ? 'info' : ($free > 500 * 1048576 ? 'pass' : 'warn'), $free === false ? 'unknown' : fmtBytes($free), 'The vault itself is small (keys, contacts, settings) — a few MB.');

/* =====================================================================
 * 6. HTTPS + SESSIONS + CRYPTO
 * ===================================================================== */
$https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https') || (($_SERVER['SERVER_PORT'] ?? '') == 443);
add('Security', 'This page was opened over HTTPS', $https ? 'pass' : 'fail', $https ? 'yes' : 'no',
    $https ? '' : 'Required: the web interface handles your mail password. Open this page with https:// — if that fails, enable a free Let\'s Encrypt certificate in your hosting control panel.');

$sp = session_save_path() ?: sys_get_temp_dir();
add('Security', 'Session storage writable', @is_writable($sp) ? 'pass' : 'warn', $sp, 'Where PHP keeps login sessions.');

$gcm = function_exists('openssl_get_cipher_methods') && in_array('aes-256-gcm', array_map('strtolower', openssl_get_cipher_methods()));
add('Security', 'AES-256-GCM available', $gcm ? 'pass' : 'warn', $gcm ? 'yes' : 'no', 'Used to protect stored session data.');
try { random_bytes(16); $rb = true; } catch (Throwable $e) { $rb = false; }
add('Security', 'Secure random numbers', $rb ? 'pass' : 'fail', $rb ? 'yes' : 'no', '');
add('Security', 'password_hash (Argon2id)', defined('PASSWORD_ARGON2ID') ? 'pass' : 'warn', defined('PASSWORD_ARGON2ID') ? 'available' : 'bcrypt only', 'Hashing the web-login password. bcrypt is acceptable.');

/* =====================================================================
 * 7. OUTBOUND CONNECTIONS
 * Many shared hosts block outgoing mail ports — this is the most
 * important test for a webmail interface.
 * ===================================================================== */
$targets = [
    ["Your IMAP server ($imapHost)", $imapHost, 993, 'tls', true],
    ["Your SMTP server ($smtpHost) — SSL", $smtpHost, 465, 'tls', true],
    ["Your SMTP server ($smtpHost) — STARTTLS", $smtpHost, 587, 'plain', false],
    ['Gmail IMAP (imap.gmail.com)', 'imap.gmail.com', 993, 'tls', false],
    ['Gmail SMTP (smtp.gmail.com)', 'smtp.gmail.com', 465, 'tls', false],
    ['Outlook IMAP (outlook.office365.com)', 'outlook.office365.com', 993, 'tls', false],
    ['Key server (keys.openpgp.org)', 'keys.openpgp.org', 443, 'tls', false],
];
$mailReach = ['imap' => false, 'smtp' => false];
foreach ($targets as [$label, $host, $port, $mode, $own]) {
    [$ok, $msg, $ms] = probe($host, $port, $mode);
    if ($own && $port == 993 && $ok) $mailReach['imap'] = true;
    if ($own && in_array($port, [465, 587]) && $ok) $mailReach['smtp'] = true;
    // individual SMTP ports are only warnings: either 465 OR 587 is enough (combined result below)
    $failStatus = ($own && $port == 993) ? 'fail' : 'warn';
    add('Connections', "$label : $port", $ok ? 'pass' : $failStatus, $ok ? "OK in {$ms} ms" : "FAILED ({$ms} ms)", $msg);
}
add('Connections', "Can send mail through $smtpHost (port 465 or 587)", $mailReach['smtp'] ? 'pass' : 'fail',
    $mailReach['smtp'] ? 'yes' : 'no',
    $mailReach['smtp'] ? '' : 'Neither SMTP port is reachable. Check the server name above, or ask your host whether outgoing connections to ports 465/587 are blocked (some hosts allow them only to their own mail server).');
if (!$mailReach['imap']) {
    add('Connections', 'Tip', 'info', 'IMAP not reachable', 'Make sure the IMAP server name above is right (your host\'s control panel lists it under "Email accounts" → "Connect devices"). If it is, your host may block outgoing port 993.');
}

/* =====================================================================
 * 8. VERDICT
 * ===================================================================== */
$fails = array_values(array_filter($results, fn($r) => $r['status'] === 'fail'));
$warns = array_values(array_filter($results, fn($r) => $r['status'] === 'warn'));
if (!$fails) {
    $verdict = ['ready', 'This server can run Sealpost Web.' . ($warns ? ' A few items are worth adjusting (yellow).' : '')];
} else {
    $blocking = array_map(fn($r) => $r['name'], $fails);
    $verdict = ['blocked', 'Not ready yet — fix the red items: ' . implode('; ', $blocking) . '.'];
}

/* =====================================================================
 * 9. OUTPUT
 * ===================================================================== */
$report = [
    'tool' => 'sealpost-check', 'version' => 1, 'generated' => gmdate('c'),
    'site' => $siteHost, 'verdict' => $verdict[0], 'summary' => $verdict[1],
    'results' => $results,
];

if (($_GET['format'] ?? '') === 'json') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

header('Content-Type: text/html; charset=utf-8');
$e = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
$icon = ['pass' => '✔', 'warn' => '!', 'fail' => '✖', 'info' => 'i'];
$sections = [];
foreach ($results as $r) $sections[$r['section']][] = $r;
?><!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Sealpost server check</title>
<style>
  :root { --bg:#111418; --card:#191d24; --line:#2a303a; --text:#e7e9ee; --muted:#9aa2af; --ok:#3ccf91; --warn:#f0b445; --bad:#ff6b6b; --info:#5aa9ff; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--text); font:15px/1.5 "Segoe UI", system-ui, sans-serif; padding:24px 16px 60px; }
  main { max-width: 980px; margin: 0 auto; }
  h1 { font-size: 22px; margin: 0 0 4px; } h2 { font-size: 15px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); margin: 28px 0 8px; }
  .verdict { border-radius: 10px; padding: 16px 18px; margin: 16px 0; font-size: 16px; border: 1px solid; }
  .verdict.ready { background: rgba(60,207,145,.1); border-color: rgba(60,207,145,.4); }
  .verdict.blocked { background: rgba(255,107,107,.1); border-color: rgba(255,107,107,.45); }
  table { width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }
  td { padding: 9px 12px; border-top: 1px solid var(--line); vertical-align: top; }
  tr:first-child td { border-top: 0; }
  td.s { width: 34px; text-align: center; font-weight: 700; }
  td.n { width: 34%; } td.v { font-family: Consolas, ui-monospace, monospace; font-size: 13px; word-break: break-word; }
  .note { color: var(--muted); font-size: 13px; font-family: "Segoe UI", system-ui, sans-serif; margin-top: 2px; }
  .pass { color: var(--ok); } .warn { color: var(--warn); } .fail { color: var(--bad); } .info { color: var(--info); }
  form.hosts { display: flex; flex-wrap: wrap; gap: 8px; align-items: end; background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 12px; }
  label { font-size: 12px; color: var(--muted); display: block; }
  input[type=text] { background: var(--bg); color: var(--text); border: 1px solid var(--line); border-radius: 6px; padding: 7px 10px; min-width: 240px; }
  button { background: #2a303a; color: var(--text); border: 1px solid var(--line); border-radius: 6px; padding: 8px 14px; cursor: pointer; }
  button.danger { background: rgba(255,107,107,.15); border-color: rgba(255,107,107,.5); color: var(--bad); }
  .muted { color: var(--muted); font-size: 13px; }
  @media (max-width: 640px) { td.n { width: auto; } tr { display: block; } td { display: block; border: 0; } td.s { display: inline-block; } }
</style></head><body><main>
  <h1>Sealpost server check</h1>
  <div class="muted"><?= $e($siteHost) ?> · PHP <?= $e(PHP_VERSION) ?> · <?= $e(gmdate('Y-m-d H:i')) ?> UTC</div>

  <div class="verdict <?= $e($verdict[0]) ?>"><?= $verdict[0] === 'ready' ? '✅' : '⛔' ?> <?= $e($verdict[1]) ?></div>

  <form class="hosts" method="get">
    <input type="hidden" name="key" value="<?= $e(ACCESS_KEY) ?>">
    <div><label>Your IMAP (incoming) server</label><input type="text" name="imap" value="<?= $e($imapHost) ?>"></div>
    <div><label>Your SMTP (outgoing) server</label><input type="text" name="smtp" value="<?= $e($smtpHost) ?>"></div>
    <button type="submit">Re-test with these servers</button>
  </form>

<?php foreach ($sections as $name => $rows): ?>
  <h2><?= $e($name) ?></h2>
  <table>
  <?php foreach ($rows as $r): ?>
    <tr>
      <td class="s <?= $r['status'] ?>"><?= $icon[$r['status']] ?></td>
      <td class="n"><?= $e($r['name']) ?></td>
      <td class="v <?= $r['status'] === 'info' ? '' : $r['status'] ?>"><?= $e($r['value']) ?><?php if ($r['note'] !== ''): ?><div class="note"><?= $e($r['note']) ?></div><?php endif; ?></td>
    </tr>
  <?php endforeach; ?>
  </table>
<?php endforeach; ?>

  <h2>When you're done</h2>
  <p class="muted">This page shows details about your server. Delete it once you've shared the result.</p>
  <form method="post" onsubmit="return confirm('Delete sealpost-check.php from the server now?')">
    <input type="hidden" name="key" value="<?= $e(ACCESS_KEY) ?>">
    <button class="danger" name="delete_self" value="1">Delete this file from the server</button>
  </form>
</main></body></html>
