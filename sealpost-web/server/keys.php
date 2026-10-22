<?php
/* =====================================================================
 * Sealpost Web — keys.php  (added 1.4.0)
 * ---------------------------------------------------------------------
 * Finds people's PUBLIC keys online, and publishes yours, for Sealpost
 * Web. Browsers aren't allowed to ask other websites directly, so your
 * server does the asking. Only public keys pass through here — never a
 * secret key or a passphrase. Only a signed-in Sealpost device can use
 * it.
 *
 * Where it looks (same as Sealpost on your PC):
 *   1. Web Key Directory (WKD) — published by the person's own mail
 *      domain, e.g. https://openpgpkey.example.com/.well-known/…
 *   2. keys.openpgp.org — the verified public key server
 *
 * Sections:
 *   0. Startup + router
 *   1. Web requests (HTTPS only, no redirects, short time limits)
 *   2. lookup  — { email } -> keys found
 *   3. publish — { armored } -> upload to keys.openpgp.org + verify email
 * ===================================================================== */

declare(strict_types=1);
define('SEALPOST', 1);
require __DIR__ . '/lib.php';

/* =================================================================
 * 0. STARTUP + ROUTER
 * ================================================================= */
ini_set('display_errors', '0');
@set_time_limit(60);
set_exception_handler(function (Throwable $e) {
    error_log('Sealpost keys: ' . $e->getMessage());
    fail(500, 'server_error', 'The server had a problem with that request.');
});
require_secure_transport();
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') fail(405, 'post_only', 'Use POST for this request.');
require_auth();

$action = (string) ($_GET['action'] ?? '');
if ($action === 'lookup') keys_lookup();
elseif ($action === 'publish') keys_publish();
else fail(404, 'unknown_action', 'Unknown request.');

/* =================================================================
 * 1. WEB REQUESTS
 *    Returns [status, body] — status 0 when the site couldn't be reached.
 * ================================================================= */
function http_req(string $url, ?string $postJson = null, int $timeout = 10): array
{
    if (!str_starts_with($url, 'https://')) return [0, ''];
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        $opts = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 6,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_MAXFILESIZE => 2 * 1048576,
            CURLOPT_USERAGENT => 'SealpostWeb/' . SEALPOST_SERVER_VERSION,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ];
        if ($postJson !== null) {
            $opts[CURLOPT_POST] = true;
            $opts[CURLOPT_POSTFIELDS] = $postJson;
            $opts[CURLOPT_HTTPHEADER] = ['Content-Type: application/json'];
        }
        curl_setopt_array($ch, $opts);
        $body = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        return [$body === false ? 0 : $status, $body === false ? '' : (string) $body];
    }
    // fallback without curl
    $ctx = stream_context_create(['http' => [
        'method' => $postJson !== null ? 'POST' : 'GET',
        'header' => $postJson !== null ? "Content-Type: application/json\r\n" : '',
        'content' => $postJson ?? '', 'timeout' => $timeout, 'follow_location' => 0, 'ignore_errors' => true,
    ]]);
    $body = @file_get_contents($url, false, $ctx, 0, 2 * 1048576);
    $status = 0;
    foreach ($http_response_header ?? [] as $h) if (preg_match('#^HTTP/\S+\s+(\d+)#', $h, $m)) $status = (int) $m[1];
    return [$status, $body === false ? '' : $body];
}

/** z-base-32 (used for WKD addresses) */
function zbase32(string $bin): string
{
    $alphabet = 'ybndrfg8ejkmcpqxot1uwisza345h769';
    $bits = '';
    foreach (str_split($bin) as $c) $bits .= str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT);
    $out = '';
    foreach (str_split($bits, 5) as $chunk) $out .= $alphabet[bindec(str_pad($chunk, 5, '0'))];
    return $out;
}

/* =================================================================
 * 2. LOOKUP — { email } -> { found: [{ source, format, data }], errors }
 *    data: base64 of the binary key (WKD) or the armored text.
 * ================================================================= */
function keys_lookup(): void
{
    $email = strtolower(trim((string) input('email', '')));
    if (!preg_match('/^([^\s@<>"]{1,64})@([a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+)$/', $email, $m)) {
        fail(400, 'bad_email', 'Enter a complete email address.');
    }
    [$local, $domain] = [$m[1], $m[2]];
    $found = [];
    $errors = [];

    // 1. Web Key Directory: "advanced" address first, then "direct"
    $hash = zbase32(sha1($local, true));
    $urls = [
        "https://openpgpkey.$domain/.well-known/openpgpkey/$domain/hu/$hash?l=" . rawurlencode($local),
        "https://$domain/.well-known/openpgpkey/hu/$hash?l=" . rawurlencode($local),
    ];
    foreach ($urls as $u) {
        [$st, $body] = http_req($u, null, 8);
        if ($st === 200 && strlen($body) > 50) {
            $found[] = ['source' => "WKD ($domain)", 'format' => 'binary', 'data' => base64_encode($body)];
            break;
        }
    }

    // 2. keys.openpgp.org
    [$st, $body] = http_req('https://keys.openpgp.org/vks/v1/by-email/' . rawurlencode($email), null, 10);
    if ($st === 200 && str_contains($body, 'BEGIN PGP PUBLIC KEY BLOCK')) {
        $found[] = ['source' => 'keys.openpgp.org', 'format' => 'armored', 'data' => $body];
    } elseif ($st !== 404 && $st !== 200) {
        $errors[] = $st === 0 ? 'keys.openpgp.org could not be reached' : 'keys.openpgp.org answered HTTP ' . $st;
    }
    reply(['found' => $found, 'errors' => $errors]);
}

/* =================================================================
 * 3. PUBLISH — { armored } (your PUBLIC key) -> keys.openpgp.org
 *    The key server emails each address a link to confirm it.
 * ================================================================= */
function keys_publish(): void
{
    $armored = (string) input('armored', '');
    if (strlen($armored) > 512000 || !str_contains($armored, '-----BEGIN PGP PUBLIC KEY BLOCK-----') || str_contains($armored, 'PRIVATE KEY')) {
        fail(400, 'bad_key', 'Only a public key can be published.');
    }
    [$st, $body] = http_req('https://keys.openpgp.org/vks/v1/upload', json_encode(['keytext' => $armored]), 15);
    if ($st !== 200) fail(502, 'keyserver', $st === 0 ? 'keys.openpgp.org could not be reached.' : 'keys.openpgp.org refused the upload (HTTP ' . $st . ').');
    $up = json_decode($body, true) ?: [];
    $pending = [];
    foreach (($up['status'] ?? []) as $addr => $state) if ($state === 'unpublished') $pending[] = $addr;
    if ($pending) {
        http_req('https://keys.openpgp.org/vks/v1/request-verify', json_encode(['token' => $up['token'] ?? '', 'addresses' => $pending]), 15);
    }
    reply(['status' => $up['status'] ?? new stdClass(), 'verificationSentTo' => $pending]);
}
