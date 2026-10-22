<?php
/* =====================================================================
 * Sealpost Web — status.php
 * ---------------------------------------------------------------------
 * Server status page (linked from the sign-in screen). It never shows
 * the setup code or anything from the vault.
 *
 * Sections:
 *   1. Gather status
 *   2. Page (HTML + CSS)
 * ===================================================================== */

declare(strict_types=1);
define('SEALPOST', 1);
require __DIR__ . '/lib.php';

/* =================================================================
 * 1. GATHER STATUS
 * ================================================================= */
ini_set('display_errors', '0');
$checks = [];
$hasVault = false;
$storageOk = false;
try {
    db();
    $storageOk = true;
    $hasVault = vault_has_users();
} catch (Throwable $e) {
    $storageOk = false;
}
$https = is_https();
$checks[] = ['Secure connection (HTTPS)', $https, $https ? 'Yes' : 'No — open this page with https://'];
$checks[] = ['Vault storage', $storageOk, $storageOk ? 'Ready (outside the public web folder)' : 'Not writable — check data_dir in config.php'];
$checks[] = ['PHP ' . PHP_VERSION, version_compare(PHP_VERSION, '8.1', '>='), version_compare(PHP_VERSION, '8.1', '>=') ? 'OK' : 'PHP 8.1 or newer is needed'];
$checks[] = ['Vault', true, $hasVault ? 'Created' : (trim((string) cfg('setup_code')) !== '' ? 'Not created yet — create it from Sealpost' : 'Not created (setup is switched off in config.php)')];
// 1.10.0: one-click updates (only what's already known — this page never asks GitHub)
$upBad = up_blockers();
$upNew = $storageOk ? up_available() : null;
$checks[] = ['One-click updates', !$upBad, $upBad ? 'Not possible here: ' . implode('; ', $upBad) . ' — upload new versions by hand'
    : ($upNew ? 'Version ' . $upNew['version'] . ' is available — Sealpost Web → Settings → Server updates' : 'Ready (Sealpost Web → Settings → Server updates)')];

// the address to type into Sealpost: this folder's URL
$scheme = $https ? 'https' : 'http';
$host = htmlspecialchars((string) ($_SERVER['HTTP_HOST'] ?? 'your-site'), ENT_QUOTES);
$path = rtrim(str_replace('\\', '/', dirname((string) ($_SERVER['SCRIPT_NAME'] ?? '/'))), '/') . '/';
$address = $scheme . '://' . $host . htmlspecialchars($path, ENT_QUOTES);

header('Cache-Control: no-store');
header('X-Robots-Tag: noindex, nofollow');
header('Referrer-Policy: no-referrer');

/* =================================================================
 * 2. PAGE
 * ================================================================= */
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Sealpost Server Status</title>
<style>
  :root { --bg:#f5f6f8; --card:#fff; --ink:#1d2026; --muted:#5d6470; --ok:#1d8a4e; --bad:#c0392b; --line:#e3e6ea; --accent:#2f6fde; }
  @media (prefers-color-scheme: dark) { :root { --bg:#14161a; --card:#1d2026; --ink:#e8eaee; --muted:#9aa1ad; --line:#2c3038; --accent:#6b9bff; } }
  body { margin:0; background:var(--bg); color:var(--ink); font:15px/1.5 "Segoe UI", system-ui, sans-serif; }
  main { max-width:560px; margin:48px auto; padding:0 16px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:24px; }
  h1 { font-size:20px; margin:0 0 4px; } p { color:var(--muted); margin:0 0 16px; }
  table { width:100%; border-collapse:collapse; } td { padding:8px 0; border-top:1px solid var(--line); vertical-align:top; }
  td:first-child { width:45%; font-weight:600; } .ok { color:var(--ok); } .bad { color:var(--bad); }
  a { color:var(--accent); }
  code { display:block; background:var(--bg); border:1px solid var(--line); border-radius:8px; padding:10px; margin-top:6px; word-break:break-all; color:var(--accent); }
</style>
</head>
<body>
<main>
  <div class="card">
    <h1>Sealpost server status</h1>
    <p>This server keeps your Sealpost devices in step. Everything stored here is encrypted on your PC first — the server can't read it.</p>
    <table>
      <?php foreach ($checks as [$name, $ok, $text]): ?>
        <tr><td><?= htmlspecialchars($name) ?></td><td class="<?= $ok ? 'ok' : 'bad' ?>"><?= htmlspecialchars($text) ?></td></tr>
      <?php endforeach; ?>
      <tr><td>Address to enter in Sealpost</td><td><code><?= $address ?></code></td></tr>
      <tr><td>Server version</td><td><?= SEALPOST_SERVER_VERSION ?></td></tr>
      <tr><td>Sealpost Web</td><td><a href="./">Open Sealpost Web</a></td></tr>
    </table>
  </div>
</main>
</body>
</html>
