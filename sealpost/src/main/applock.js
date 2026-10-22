/* =====================================================================
 * Sealpost — applock.js   (added 1.1.0)
 * ---------------------------------------------------------------------
 * App lock: Sealpost asks for a PIN (or Windows Hello) when it starts,
 * after a period of inactivity, and when Windows is locked.
 *
 * While locked, the main process refuses every request from the window
 * except the unlock requests (see the gate in main.js), so nothing —
 * mail, keys, contacts — can be read until you unlock.
 *
 * Sections:
 *   1. PIN hashing (scrypt, never stored in plain text) + attempt limit
 *   2. Windows Hello (fingerprint / face / Windows PIN) via PowerShell
 * ===================================================================== */

const crypto = require('crypto');
const { execFile } = require('child_process');

/* =================================================================
 * 1. PIN
 * ================================================================= */
function hashPin(pin, saltHex) {
  const salt = saltHex ? Buffer.from(saltHex, 'hex') : crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(pin), salt, 32, { N: 16384, r: 8, p: 1 });
  return { salt: salt.toString('hex'), hash: hash.toString('hex') };
}

function checkPin(pin, cfg) {
  if (!cfg || !cfg.salt || !cfg.hash) return false;
  const { hash } = hashPin(pin, cfg.salt);
  const a = Buffer.from(hash, 'hex'), b = Buffer.from(cfg.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// After 5 wrong PINs, wait 30 seconds between tries (doubles each time).
// The counter is saved to disk so restarting Sealpost doesn't reset it.
let attempts = { count: 0, until: 0 };
let persist = null; // { load(): obj|null, save(obj) }
function setAttemptStore(p) {
  persist = p;
  try { const a = p.load(); if (a && typeof a.count === 'number') attempts = { count: a.count, until: a.until || 0 }; } catch { /* ignore */ }
}
function saveAttempts() { try { if (persist) persist.save(attempts); } catch { /* ignore */ } }
function attemptAllowed() {
  if (Date.now() < attempts.until) {
    const err = new Error(`Too many wrong attempts. Try again in ${Math.ceil((attempts.until - Date.now()) / 1000)} seconds.`);
    err.code = 'LOCK_WAIT';
    throw err;
  }
}
function recordFailure() {
  attempts.count++;
  if (attempts.count >= 5) attempts.until = Date.now() + 30000 * Math.pow(2, Math.min(attempts.count - 5, 8));
  saveAttempts();
}
function recordSuccess() { attempts = { count: 0, until: 0 }; saveAttempts(); }

/* =================================================================
 * 2. WINDOWS HELLO
 * Uses Windows' own UserConsentVerifier (the same prompt other apps
 * show for fingerprint / face / Windows Hello PIN). Electron can't call
 * it directly, so a short PowerShell script does.
 * ================================================================= */
const PS_PRELUDE = `
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
  $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation\`1' })[0]
function Await($op, $type) { $t = $asTask.MakeGenericMethod($type).Invoke($null, @($op)); $t.Wait(-1) | Out-Null; $t.Result }
$null = [Windows.Security.Credentials.UI.UserConsentVerifier, Windows.Security.Credentials.UI, ContentType = WindowsRuntime]
`;

function runPowerShell(script, timeoutMs) {
  return new Promise(resolve => {
    if (process.platform !== 'win32') return resolve({ ok: false, out: 'Windows Hello is only available on Windows' });
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script],
      { windowsHide: true, timeout: timeoutMs },
      (err, stdout, stderr) => resolve({ ok: !err, out: String(stdout || '').trim(), err: String(stderr || err || '').trim() }));
  });
}

/** 'Available' | 'DeviceNotPresent' | 'NotConfiguredForUser' | 'DisabledByPolicy' | ... | 'Unsupported' */
async function helloAvailability() {
  const r = await runPowerShell(PS_PRELUDE +
    `Await ([Windows.Security.Credentials.UI.UserConsentVerifier]::CheckAvailabilityAsync()) ([Windows.Security.Credentials.UI.UserConsentVerifierAvailability])`, 20000);
  return r.ok && r.out ? r.out.split(/\r?\n/).pop() : 'Unsupported';
}

/** Shows the Windows Hello prompt. Resolves true only when Windows says 'Verified'. */
async function helloVerify(message) {
  const msg = String(message || 'Unlock Sealpost').replace(/'/g, "''");
  const r = await runPowerShell(PS_PRELUDE +
    `Await ([Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync('${msg}')) ([Windows.Security.Credentials.UI.UserConsentVerificationResult])`, 120000);
  const result = r.out ? r.out.split(/\r?\n/).pop() : '';
  return { verified: result === 'Verified', result: result || r.err || 'Failed' };
}

module.exports = { hashPin, checkPin, setAttemptStore, attemptAllowed, recordFailure, recordSuccess, helloAvailability, helloVerify };
