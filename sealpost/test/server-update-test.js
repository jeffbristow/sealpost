/* Sealpost Server 1.10.0 self-test: one-click server updates (update.php,
 * lib.php section 8). Runs the real server with `php -S` and a local
 * update feed; packages are signed with a throwaway test key.
 * Needs `php` with pdo_sqlite, zip, curl and sodium (skipped otherwise). */
const os = require('os');
const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const assert = require('assert');
const { spawn, spawnSync } = require('child_process');
const { Store } = require('../src/main/store');
const { PgpEngine } = require('../src/main/pgp');
const { ContactStore } = require('../src/main/contacts');
const { SyncService, deriveKeys } = require('../src/main/sync');

const SERVER_SRC = process.env.SEALPOST_SERVER || path.join(__dirname, '..', '..', 'sealpost-web', 'server');
const PORT = 8990 + Math.floor(Math.random() * 100);
let passed = 0;
const ok = (c, m) => { assert(c, m); passed++; console.log('  ✓', m); };
const sha = b => crypto.createHash('sha256').update(b).digest('hex');

/** Zips <dir> as "sealpost-server/…" with PHP's ZipArchive (no zip tool needed). */
function makeZip(dir, out) {
  const code = `$z=new ZipArchive();$z->open($argv[2],ZipArchive::CREATE|ZipArchive::OVERWRITE);
    $it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($argv[1],FilesystemIterator::SKIP_DOTS));
    foreach($it as $f){$rel=str_replace('\\\\','/',substr($f->getPathname(),strlen($argv[1])+1));$z->addFile($f->getPathname(),'sealpost-server/'.$rel);}
    $z->close();`;
  const r = spawnSync('php', ['-r', code, dir, out]);
  if (r.status !== 0) throw new Error('zip: ' + r.stderr);
}

function signFor(key, version, zip) {
  const h = sha(fs.readFileSync(zip));
  const sig = crypto.sign(null, Buffer.from(`sealpost-server-update-v1|${version}|${h}`), key).toString('base64');
  return JSON.stringify({ v: 1, kind: 'sealpost-server', version, sha256: h, sig });
}

(async () => {
  const mods = spawnSync('php', ['-m']).stdout?.toString().toLowerCase() || '';
  if (!/\bpdo_sqlite\b/.test(mods) || !/\bzip\b/.test(mods) || !/\bcurl\b/.test(mods) || !/\bsodium\b/.test(mods) || !fs.existsSync(SERVER_SRC)) {
    console.log('server-update: php (with pdo_sqlite, zip, curl, sodium) or server files not found — test skipped'); return;
  }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sealpost-upd-'));
  const www = path.join(root, 'www');
  fs.cpSync(SERVER_SRC, www, { recursive: true });
  fs.rmSync(path.join(www, 'config.php'), { force: true });   // the template, as on a fresh install
  const libFile = path.join(www, 'lib.php');
  const current = /SEALPOST_SERVER_VERSION = '([^']+)'/.exec(fs.readFileSync(libFile, 'utf8'))[1];

  // throwaway signing keys: "good" stands in for Sealpost's key, "other" is someone else's
  const good = crypto.generateKeyPairSync('ed25519'), other = crypto.generateKeyPairSync('ed25519');
  const goodPub = good.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');
  fs.writeFileSync(libFile, fs.readFileSync(libFile, 'utf8').replace(/UPDATE_PUBKEY = '[^']+'/, `UPDATE_PUBKEY = '${goodPub}'`));

  // the local update feed (answers whatever "feed" holds)
  const feed = {};
  const srv = http.createServer((req, res) => {
    const body = feed[req.url];
    if (body === undefined) { res.writeHead(404); return res.end(); }
    res.writeHead(200); res.end(body);
  });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  const feedUrl = `http://127.0.0.1:${srv.address().port}`;
  const cfg = fs.readFileSync(path.join(www, 'config.example.php'), 'utf8')
    .replace("'setup_code' => 'CHANGE-THIS-CODE'", "'setup_code' => 'TEST-SETUP-CODE'")
    .replace(/return \[/, `return [\n    'update_urls' => ['${feedUrl}/server-update.json'],`);
  fs.writeFileSync(path.join(www, 'config.php'), cfg);

  // the new version: same files, version 9.9.9, a changed index.php, a new file — and a config.php that must be ignored
  const NEW = '9.9.9';
  const pkg = path.join(root, 'pkg');
  fs.cpSync(SERVER_SRC, pkg, { recursive: true });
  fs.writeFileSync(path.join(pkg, 'lib.php'), fs.readFileSync(libFile, 'utf8').replace(`SEALPOST_SERVER_VERSION = '${current}'`, `SEALPOST_SERVER_VERSION = '${NEW}'`));
  fs.appendFileSync(path.join(pkg, 'index.php'), '\n<!-- new index -->\n');
  fs.writeFileSync(path.join(pkg, 'web', 'brand-new.js'), '// added in 9.9.9\n');
  fs.writeFileSync(path.join(pkg, 'config.php'), "<?php return ['setup_code' => 'FROM-THE-PACKAGE'];");
  const zip = path.join(root, 'pkg.zip');
  makeZip(pkg, zip);
  const zipBytes = fs.readFileSync(zip);
  const setFeed = sigText => {
    feed['/server-update.json'] = JSON.stringify({ version: NEW, url: feedUrl + '/pkg.zip', sha256: '', size: '1 MB', note: 'test' });
    feed['/pkg.zip'] = zipBytes;
    feed['/pkg.zip.sig'] = sigText;
  };

  const php = spawn('php', ['-S', '127.0.0.1:' + PORT, '-t', www], { stdio: 'ignore' });
  const url = `http://127.0.0.1:${PORT}/`;
  const post = async (file, action, body, token) => {
    const r = await fetch(`${url}${file}?action=${action}`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(token ? { 'X-Sealpost-Token': token } : {}) }, body: JSON.stringify(body || {}) });
    return { status: r.status, json: await r.json() };
  };
  try {
    for (let i = 0; i < 50; i++) { try { await fetch(url + 'api.php?action=ping'); break; } catch { await new Promise(r => setTimeout(r, 100)); } }

    // a vault + a signed-in web device
    const dir = path.join(root, 'pc'); fs.mkdirSync(dir);
    const store = new Store(dir), pgp = new PgpEngine(dir); await pgp.load();
    const pc = new SyncService({ dataDir: dir, store, pgp, contacts: new ContactStore(dir) });
    await pc.connect({ server: url, username: 'owner', passphrase: 'vault passphrase 1', create: true, setupCode: 'TEST-SETUP-CODE' });
    const { authKey } = await deriveKeys('vault passphrase 1', 'owner');
    const login = await post('api.php', 'login', { username: 'owner', authKey, deviceName: 'Test browser', kind: 'web' });
    const token = login.json.token;
    ok(!!token, 'signed in as a web device');

    const configBefore = fs.readFileSync(path.join(www, 'config.php'));
    const libBefore = fs.readFileSync(libFile);
    const vaultFile = path.join(root, 'sealpost-data', 'vault.sqlite');
    ok(fs.existsSync(vaultFile), 'the vault is outside the website folder');

    // not signed in
    ok((await post('update.php', 'status')).status === 401, 'update.php refuses requests that are not signed in');

    // status: sees the new version
    setFeed(signFor(good.privateKey, NEW, zip));
    const st = await post('update.php', 'check', {}, token);
    ok(st.json.ok && st.json.current === current && st.json.update && st.json.update.version === NEW, `status: ${current} → ${NEW} available`);
    ok(Array.isArray(st.json.blockers) && st.json.blockers.length === 0, 'nothing stops an update here');

    // a package that doesn't match its signature
    const tampered = JSON.parse(signFor(good.privateKey, NEW, zip)); tampered.sha256 = 'a'.repeat(64);
    setFeed(JSON.stringify(tampered));
    let r = await post('update.php', 'install', {}, token);
    ok(!r.json.ok && /does not match its signature/.test(r.json.message), 'refused: file changed after signing');
    ok(fs.readFileSync(libFile).equals(libBefore), '…and nothing was changed');

    // signed by someone else
    setFeed(signFor(other.privateKey, NEW, zip));
    r = await post('update.php', 'install', {}, token);
    ok(!r.json.ok && /NOT signed by Sealpost/.test(r.json.message), 'refused: signed with another key');
    ok(fs.readFileSync(libFile).equals(libBefore) && !fs.existsSync(path.join(www, 'web', 'brand-new.js')), '…and nothing was changed');

    // the real thing
    setFeed(signFor(good.privateKey, NEW, zip));
    r = await post('update.php', 'install', {}, token);
    ok(r.json.ok && r.json.current === NEW, 'installed: ' + r.json.message);
    ok(fs.readFileSync(libFile, 'utf8').includes(`SEALPOST_SERVER_VERSION = '${NEW}'`), 'lib.php is the new version');
    ok(fs.readFileSync(path.join(www, 'index.php'), 'utf8').includes('<!-- new index -->'), 'changed file replaced');
    ok(fs.existsSync(path.join(www, 'web', 'brand-new.js')), 'new file added');
    ok(fs.readFileSync(path.join(www, 'config.php')).equals(configBefore), 'config.php untouched (the package\'s config.php was ignored)');
    ok(!fs.readdirSync(www, { recursive: true }).some(f => /\.sp-(new|old)$/.test(String(f))), 'no leftover temporary files');
    const after = await pc.sync();
    ok(after && after.result, 'the vault still works after the update (sync ran)');
    ok(r.json.undo === current, 'Undo offers ' + current);

    // undo
    r = await post('update.php', 'undo', {}, token);
    ok(r.json.ok && r.json.current === current, 'undo: ' + r.json.message);
    ok(fs.readFileSync(libFile).equals(libBefore), 'lib.php is back');
    ok(!fs.existsSync(path.join(www, 'web', 'brand-new.js')), 'the added file is gone');
    ok(!fs.readFileSync(path.join(www, 'index.php'), 'utf8').includes('<!-- new index -->'), 'index.php is back');
    ok(fs.readFileSync(path.join(www, 'config.php')).equals(configBefore), 'config.php still untouched');
    ok(!r.json.undo, 'nothing left to undo');

    console.log(`\nserver-update tests: ${passed} passed`);
  } finally { php.kill(); srv.close(); }
})().catch(e => { console.error('FAILED:', e); process.exit(1); });
