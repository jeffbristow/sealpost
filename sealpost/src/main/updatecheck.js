/* =====================================================================
 * Sealpost — updatecheck.js   (added 1.12.0)
 * ---------------------------------------------------------------------
 * "Check for updates" in Settings -> About & updates. Asks GitHub which
 * desktop release is newest (github.com/jeffbristow/sealpost/releases)
 * and, when asked, downloads that release's .sealpost update file. The
 * file then goes through the same checks as "Install update file…".
 *
 * Only runs when the user clicks the button — Sealpost never phones home
 * on its own.
 *
 * Sections:
 *   1. Which releases count (desktop tags "v1.2.3"; not "server-v…")
 *   2. checkForUpdate — newest release vs the running version
 *   3. downloadUpdate — fetch the .sealpost file to a local path
 * ===================================================================== */

const fs = require('fs');

const REPO = 'jeffbristow/sealpost';
const RELEASES_API = `https://api.github.com/repos/${REPO}/releases?per_page=30`;
const RELEASES_PAGE = `https://github.com/${REPO}/releases`;
const MAX_UPDATE_BYTES = 200 * 1024 * 1024;

/* ---------- 1. Which releases count ---------- */
// Desktop releases are tagged v<desktop version>; server releases are
// tagged server-v<server version> and are skipped here.
const DESKTOP_TAG = /^v(\d+\.\d+\.\d+)$/;

function cmpVersion(a, b) {
  const pa = String(a).split('.').map(n => parseInt(n, 10) || 0);
  const pb = String(b).split('.').map(n => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d > 0 ? 1 : -1;
  }
  return 0;
}

/** Newest published desktop release in a GitHub releases list, or null. */
function newestDesktopRelease(list) {
  let best = null;
  for (const r of Array.isArray(list) ? list : []) {
    if (!r || r.draft || r.prerelease) continue;
    const m = DESKTOP_TAG.exec(String(r.tag_name || ''));
    if (!m) continue;
    if (!best || cmpVersion(m[1], best.version) > 0) best = { version: m[1], release: r };
  }
  return best;
}

/* ---------- 2. checkForUpdate ---------- */
/** -> { current, latest, newer, page, notes, file: { name, url, size } | null } */
async function checkForUpdate({ current, fetch = globalThis.fetch } = {}) {
  let res;
  try {
    res = await fetch(RELEASES_API, {
      headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'Sealpost/' + current },
      signal: AbortSignal.timeout(15000)
    });
  } catch {
    throw new Error('Couldn\'t reach GitHub to check for updates. Check your internet connection.');
  }
  if (!res.ok) throw new Error(`GitHub answered ${res.status} when checking for updates. Try again later.`);
  const best = newestDesktopRelease(await res.json());
  if (!best) return { current, latest: null, newer: false, page: RELEASES_PAGE, notes: '', file: null };

  const want = `Sealpost-${best.version}.sealpost`;
  const asset = (best.release.assets || []).find(a => a && a.name === want)
    || (best.release.assets || []).find(a => a && /\.sealpost$/i.test(a.name || ''));
  return {
    current,
    latest: best.version,
    newer: cmpVersion(best.version, current) > 0,
    page: /^https:\/\/github\.com\//.test(best.release.html_url || '') ? best.release.html_url : RELEASES_PAGE,
    notes: String(best.release.body || '').slice(0, 4000),
    file: asset && /^https:\/\/github\.com\//.test(asset.browser_download_url || '')
      ? { name: asset.name, url: asset.browser_download_url, size: asset.size || 0 }
      : null
  };
}

/* ---------- 3. downloadUpdate ---------- */
/** Downloads a GitHub release asset to <dest>. Returns the byte count. */
async function downloadUpdate(url, dest, { fetch = globalThis.fetch } = {}) {
  if (!/^https:\/\/github\.com\//.test(String(url))) throw new Error('Updates are only downloaded from github.com.');
  let res;
  try {
    res = await fetch(url, { headers: { 'User-Agent': 'Sealpost' }, signal: AbortSignal.timeout(300000) });
  } catch {
    throw new Error('The update download failed. Check your internet connection and try again.');
  }
  if (!res.ok) throw new Error(`The update download failed (GitHub answered ${res.status}).`);
  const buf = Buffer.from(await res.arrayBuffer());
  if (!buf.length || buf.length > MAX_UPDATE_BYTES) throw new Error('The downloaded update file has the wrong size.');
  fs.writeFileSync(dest, buf);
  return buf.length;
}

module.exports = { checkForUpdate, downloadUpdate, newestDesktopRelease, cmpVersion, RELEASES_PAGE, REPO };
