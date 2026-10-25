/* Sealpost 1.12.0 self-test: "Check for updates" against GitHub releases
 * (updatecheck.js). Uses a fake fetch — no network needed. */
const os = require('os');
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const { checkForUpdate, downloadUpdate, newestDesktopRelease, RELEASES_PAGE } = require('../src/main/updatecheck');

let passed = 0;
const ok = (c, m) => { assert(c, m); passed++; console.log('  ✓', m); };
const rejects = async (p, re, m) => {
  try { await p; } catch (e) { ok(re.test(e.message), m + ' (' + e.message + ')'); return; }
  assert.fail(m + ': did not throw');
};

const asset = v => ({ name: `Sealpost-${v}.sealpost`, size: 5242880, browser_download_url: `https://github.com/jeffbristow/sealpost/releases/download/v${v}/Sealpost-${v}.sealpost` });
const RELEASES = [
  { tag_name: 'server-v1.11.0', html_url: 'https://github.com/jeffbristow/sealpost/releases/tag/server-v1.11.0', assets: [] },
  { tag_name: 'v1.13.0', prerelease: true, assets: [asset('1.13.0')] },
  { tag_name: 'v1.14.0', draft: true, assets: [asset('1.14.0')] },
  { tag_name: 'v1.12.0', html_url: 'https://github.com/jeffbristow/sealpost/releases/tag/v1.12.0', body: 'Check for updates', assets: [{ name: 'Sealpost Setup 1.12.0.exe' }, asset('1.12.0')] },
  { tag_name: 'v1.9.2', assets: [asset('1.9.2')] },
  { tag_name: 'v1.11.0', assets: [asset('1.11.0')] }
];
const fakeFetch = (body, status = 200) => async (url, opts) => {
  fakeFetch.last = { url, opts };
  return { ok: status < 300, status, json: async () => body, arrayBuffer: async () => Buffer.from(body) };
};

(async () => {
  console.log('update check (1.12.0)');
  const best = newestDesktopRelease(RELEASES);
  ok(best.version === '1.12.0', 'newest desktop release: skips server-v tags, drafts and prereleases; 1.12.0 > 1.11.0 > 1.9.2');
  ok(newestDesktopRelease([]) === null && newestDesktopRelease(null) === null, 'no releases -> null');

  let u = await checkForUpdate({ current: '1.11.0', fetch: fakeFetch(RELEASES) });
  ok(/^https:\/\/api\.github\.com\/repos\/jeffbristow\/sealpost\/releases/.test(fakeFetch.last.url), 'asks the GitHub releases API for jeffbristow/sealpost');
  ok(u.newer && u.latest === '1.12.0' && u.current === '1.11.0', '1.11.0 -> 1.12.0 is offered');
  ok(u.file && u.file.name === 'Sealpost-1.12.0.sealpost' && /^https:\/\/github\.com\//.test(u.file.url), 'picks the .sealpost update file, not the installer');
  ok(u.page === 'https://github.com/jeffbristow/sealpost/releases/tag/v1.12.0' && u.notes === 'Check for updates', 'release page + notes');

  u = await checkForUpdate({ current: '1.12.0', fetch: fakeFetch(RELEASES) });
  ok(!u.newer, 'same version -> nothing to install');
  u = await checkForUpdate({ current: '1.20.0', fetch: fakeFetch(RELEASES) });
  ok(!u.newer, 'newer local version (e.g. a dev build) -> nothing to install');

  u = await checkForUpdate({ current: '1.11.0', fetch: fakeFetch([{ tag_name: 'v1.12.0', assets: [{ name: 'x.sealpost', browser_download_url: 'https://evil.example/x.sealpost' }] }]) });
  ok(u.newer && u.file === null && u.page === RELEASES_PAGE, 'download links outside github.com are ignored');

  await rejects(checkForUpdate({ current: '1.11.0', fetch: fakeFetch([], 403) }), /GitHub answered 403/, 'GitHub error is reported');
  await rejects(checkForUpdate({ current: '1.11.0', fetch: async () => { throw new Error('ENOTFOUND'); } }), /Couldn't reach GitHub/, 'offline is reported');

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sp-upd-'));
  const dest = path.join(dir, 'incoming.tmp');
  const n = await downloadUpdate(asset('1.12.0').browser_download_url, dest, { fetch: fakeFetch('asar bytes') });
  ok(n === 10 && fs.readFileSync(dest, 'utf8') === 'asar bytes', 'downloads the update file');
  await rejects(downloadUpdate('https://evil.example/x.sealpost', dest, { fetch: fakeFetch('x') }), /only downloaded from github\.com/, 'refuses non-GitHub download URLs');
  await rejects(downloadUpdate(asset('1.12.0').browser_download_url, dest, { fetch: fakeFetch('', 404) }), /GitHub answered 404/, 'failed download is reported');
  fs.rmSync(dir, { recursive: true, force: true });

  console.log(`\n${passed} passed`);
})().catch(e => { console.error('FAILED:', e.message); process.exit(1); });
