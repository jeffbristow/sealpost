<?php
/* =====================================================================
 * Sealpost Server — update.php  (added 1.10.0)
 * ---------------------------------------------------------------------
 * What Sealpost Web's update notice and Settings → Server updates talk
 * to. The work happens in lib.php section 8: GitHub only, signed
 * packages only, config.php and the vault never touched, Undo.
 *
 * Only a signed-in Sealpost device can use it. That's enough: an
 * install can only ever put a newer, Sealpost-signed version in place.
 *
 * Requests: POST update.php?action=…  (JSON reply, like api.php)
 *   status   this version + the newest known (asks GitHub every 12 h)
 *   check    ask GitHub now (at most once a minute)
 *   install  install the newer version
 *   undo     go back to the version before the last update
 *
 * Sections:
 *   0. Startup + router
 *   1. status / check
 *   2. install / undo
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
    error_log('Sealpost update: ' . $e->getMessage());
    fail(500, 'server_error', 'The server had a problem with that request.');
});
require_secure_transport();
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') fail(405, 'post_only', 'Use POST for this request.');
require_auth();

$action = (string) ($_GET['action'] ?? '');
if ($action === 'status') reply(up_state(up_check(false)));
elseif ($action === 'check') update_check();
elseif ($action === 'install') update_install();
elseif ($action === 'undo') update_undo();
else fail(404, 'unknown_action', 'Unknown request.');

/* =================================================================
 * 1. CHECK — asks GitHub now, at most once a minute
 * ================================================================= */
function update_check(): void
{
    $c = up_read('check.json');
    reply(up_state(up_check(time() - (int) ($c['checked'] ?? 0) >= 60)));
}

/* =================================================================
 * 2. INSTALL / UNDO
 * ================================================================= */
function update_install(): void
{
    [$ok, $msg] = up_install();
    if (!$ok) fail(409, 'update_failed', $msg, up_state());
    reply(['message' => $msg] + up_state());
}

function update_undo(): void
{
    [$ok, $msg] = up_restore();
    if (!$ok) fail(409, 'undo_failed', $msg, up_state());
    reply(['message' => $msg] + up_state());
}
