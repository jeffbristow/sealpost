/* =====================================================================
 * Sealpost — bootstrap.js   (app entry point, added in 1.0.1)
 * ---------------------------------------------------------------------
 * Lets Sealpost update itself from a single ".sealpost" update file,
 * without reinstalling.
 *
 *   Update files installed through Settings → "Install update file…"
 *   are stored in:   %APPDATA%\Sealpost\updates\sealpost-<version>.asar
 *
 * On every start this loader:
 *   1. Finds the newest valid update file in that folder.
 *   2. If it is NEWER than the installed version, runs the app from it;
 *      otherwise runs the installed copy (so installing a newer full
 *      installer later always wins).
 *   3. Deletes older update files it no longer needs.
 *   4. If an update fails to load, its version is recorded as bad and
 *      the installed copy runs instead — a broken update can't lock you out.
 * ===================================================================== */

const { app } = require('electron');
const path = require('path');
const { readPackageJson, fs } = require('./asarinfo'); // 1.0.3: reads update files without locking them

const installedVersion = require('../../package.json').version;

/* ---------- Section: Linux AppImage sandbox (1.8.0) ----------
 * Ubuntu 23.10+ (and some other distributions) block the kind of sandbox
 * Chromium needs unless the app was installed as a system package. An
 * AppImage can't be, so there Sealpost turns Chromium's process sandbox
 * off instead of refusing to start. Sealpost's own protections (isolated
 * pages, no scripts in emails, strict content policy) stay on. The .deb
 * package installs properly and keeps the sandbox. */
if (process.platform === 'linux' && process.env.APPIMAGE) {
  let restricted = false;
  try { restricted = fs.readFileSync('/proc/sys/kernel/apparmor_restrict_unprivileged_userns', 'utf8').trim() === '1'; } catch { /* setting not present: not restricted */ }
  try { if (!restricted && fs.readFileSync('/proc/sys/kernel/unprivileged_userns_clone', 'utf8').trim() === '0') restricted = true; } catch { /* ignore */ }
  if (restricted) app.commandLine.appendSwitch('no-sandbox');
}

/* ---------- Section: version compare ("1.0.10" > "1.0.9") ---------- */
function cmpVersion(a, b) {
  const pa = String(a).split('.').map(n => parseInt(n, 10) || 0);
  const pb = String(b).split('.').map(n => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d > 0 ? 1 : -1;
  }
  return 0;
}

/* ---------- Section: pick the newest update file ---------- */
const updatesDir = path.join(app.getPath('userData'), 'updates');
const badFile = path.join(updatesDir, 'bad-versions.json');
const readBad = () => { try { return JSON.parse(fs.readFileSync(badFile, 'utf8')); } catch { return []; } };

function findUpdate() {
  let names = [];
  try { names = fs.readdirSync(updatesDir); } catch { return null; }

  // tidy up leftovers from interrupted installs (incl. the 1.0.1 EBUSY bug)
  for (const f of names) {
    if (/^incoming-.*\.(asar|tmp)$/.test(f) || /\.tmp$/.test(f)) {
      try { fs.unlinkSync(path.join(updatesDir, f)); } catch { /* still locked; next start */ }
    }
  }

  const bad = readBad();
  const candidates = [];
  for (const f of names.filter(n => /^sealpost-[\d.]+\.asar$/.test(n))) {
    const full = path.join(updatesDir, f);
    try {
      const pkg = readPackageJson(full);
      if (pkg.name === 'sealpost' && pkg.__hasMain && !bad.includes(pkg.version)) candidates.push({ full, file: f, version: pkg.version });
      else if (bad.includes(pkg.version)) { try { fs.unlinkSync(full); } catch { /* ignore */ } }
    } catch { /* unreadable — ignore */ }
  }
  candidates.sort((x, y) => cmpVersion(y.version, x.version));
  const best = candidates[0] && cmpVersion(candidates[0].version, installedVersion) > 0 ? candidates[0] : null;

  // remove update files that will never be used (nothing has opened them, so no lock)
  for (const c of candidates) {
    if (best && c.full === best.full) continue;
    try { fs.unlinkSync(c.full); } catch { /* ignore */ }
  }
  return best;
}

/* ---------- Section: start the app ---------- */
let started = false;
try {
  const upd = findUpdate();
  if (upd) {
    process.env.SEALPOST_RUNNING_VERSION = upd.version;
    process.env.SEALPOST_UPDATE_FILE = upd.full;
    require(path.join(upd.full, 'src', 'main', 'main.js'));
    started = true;
  }
} catch (err) {
  // update failed to load: set it aside and fall back to installed copy
  console.error('Update failed to load, using installed version:', err);
  // (file is locked while open, so record the version as bad instead of renaming it)
  try {
    const bad = readBad();
    bad.push(process.env.SEALPOST_RUNNING_VERSION);
    fs.writeFileSync(badFile, JSON.stringify([...new Set(bad)]));
  } catch { /* ignore */ }
}

if (!started) {
  process.env.SEALPOST_RUNNING_VERSION = installedVersion;
  delete process.env.SEALPOST_UPDATE_FILE;
  require('./main.js');
}

