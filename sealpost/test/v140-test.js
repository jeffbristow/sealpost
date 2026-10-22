/* Sealpost 1.4.0 self-test: encrypted sync between two PCs through the
 * PHP sync server. Needs `php` on the PATH (skipped otherwise).
 * Run with `npm test`. */
const os = require('os');
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const { spawn, spawnSync } = require('child_process');
const { Store } = require('../src/main/store');
const { PgpEngine } = require('../src/main/pgp');
const { ContactStore } = require('../src/main/contacts');
const { SyncService, normalizeServer } = require('../src/main/sync');

const SERVER_SRC = process.env.SEALPOST_SERVER || path.join(__dirname, '..', '..', 'sealpost-web', 'server');
const PORT = 8790 + Math.floor(Math.random() * 100);

let passed = 0;
const ok = (cond, msg) => { assert(cond, msg); passed++; console.log('  ✓', msg); };

async function device(root, name) {
  const dir = path.join(root, name);
  fs.mkdirSync(dir, { recursive: true });
  const store = new Store(dir);
  const pgp = new PgpEngine(dir); await pgp.load();
  const contacts = new ContactStore(dir);
  const events = [];
  const sync = new SyncService({ dataDir: dir, store, pgp, contacts, appVersion: 'test', onEvent: (t, d) => events.push([t, d]) });
  return { dir, store, pgp, contacts, sync, events, name };
}

(async () => {
  if (spawnSync('php', ['-v']).status !== 0 || !fs.existsSync(SERVER_SRC)) { console.log('v140: php or server files not found — sync test skipped'); return; }

  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sealpost-140-'));
  const www = path.join(root, 'www');
  fs.cpSync(SERVER_SRC, www, { recursive: true });
  // a fresh clone has only the template (the real config.php isn't in git)
  if (!fs.existsSync(path.join(www, 'config.php'))) fs.copyFileSync(path.join(www, 'config.example.php'), path.join(www, 'config.php'));
  const php = spawn('php', ['-S', '127.0.0.1:' + PORT, '-t', www], { stdio: 'ignore' });
  const url = `http://127.0.0.1:${PORT}/`;
  try {
    for (let i = 0; i < 50; i++) { try { await fetch(url + 'api.php?action=ping'); break; } catch { await new Promise(r => setTimeout(r, 100)); } }
    const setupCode = (fs.readFileSync(path.join(www, 'config.php'), 'utf8').match(/'setup_code'\s*=>\s*'([^']+)'/) || [])[1];

    ok(normalizeServer('jeffbristow.com/mysite/SealPost') === 'https://jeffbristow.com/mysite/SealPost/api.php', 'server address normalised');
    assert.throws(() => normalizeServer('http://example.com/'), /https/);
    ok(true, 'plain http refused for remote servers');

    /* ---------- PC A: some data, then create the vault ---------- */
    const A = await device(root, 'A');
    A.store.setSettings({ defaultEncrypt: true, pageSize: 75, appLock: { enabled: true, hash: 'PINHASH-A' } });
    const accA = A.store.saveAccount({ name: 'Jeff', email: 'jeff@zoho.test', imapHost: 'imappro.zoho.com', smtpHost: 'smtppro.zoho.com', password: 'Zoho-Secret-Pw' });
    const myKey = await A.pgp.generate({ name: 'Jeff', email: 'jeff@zoho.test', passphrase: 'key-pass-123' });
    const ann = A.contacts.save({ name: 'Ann Example', emails: ['ann@friend.test'], notes: 'met at conference' });

    const probe = await A.sync.probe(url);
    ok(probe.vault === false && probe.setupOpen === true, 'probe: empty server offers vault creation');
    await assert.rejects(A.sync.connect({ server: url, username: 'jeff', passphrase: 'vault passphrase 1', create: true, setupCode: 'WRONG-CODE', deviceName: 'PC-A' }), /setup code/);
    ok(true, 'wrong setup code refused');
    let st = await A.sync.connect({ server: url, username: 'Jeff', passphrase: 'vault passphrase 1', create: true, setupCode, deviceName: 'PC-A' });
    ok(st.connected && !st.result.error && st.result.pushed === 4, 'vault created and first upload done (settings, account, contact, key): ' + JSON.stringify(st.result));

    /* ---------- zero knowledge: nothing readable on the server ---------- */
    const dbFile = path.join(root, 'sealpost-data', 'vault.sqlite');
    const raw = fs.readFileSync(dbFile, 'latin1') + (fs.existsSync(dbFile + '-wal') ? fs.readFileSync(dbFile + '-wal', 'latin1') : '');
    for (const s of ['Zoho-Secret-Pw', 'jeff@zoho.test', 'imappro', 'Ann Example', 'ann@friend.test', 'conference', 'BEGIN PGP', 'vault passphrase', 'PINHASH']) ok(!raw.includes(s), `server database does not contain "${s}"`);

    /* ---------- PC B: has its own copy of Ann + another contact, joins ---------- */
    const B = await device(root, 'B');
    B.contacts.save({ name: 'Ann (old)', emails: ['ann@friend.test'] });
    B.contacts.save({ name: 'Bob', emails: ['bob@b.test'] });
    B.store.setSettings({ appLock: { enabled: true, hash: 'PINHASH-B' } });
    await assert.rejects(B.sync.connect({ server: url, username: 'jeff', passphrase: 'not the passphrase', deviceName: 'PC-B' }), /Wrong username or passphrase/);
    ok(true, 'wrong vault passphrase refused');
    st = await B.sync.connect({ server: url, username: 'jeff', passphrase: 'vault passphrase 1', deviceName: 'PC-B' });
    ok(!st.result.error, 'PC-B connected: ' + JSON.stringify(st.result));
    const bAcc = B.store.getAccount(accA.id);
    ok(bAcc.password === 'Zoho-Secret-Pw' && bAcc.imapHost === 'imappro.zoho.com', 'account with password arrived on PC-B');
    ok(B.pgp.privateKeys.has(myKey.fingerprint) && B.pgp.meta[myKey.fingerprint].trust === 'ultimate', 'secret key + trust arrived on PC-B');
    ok(B.contacts.list.length === 2 && B.contacts.get(ann.id).name === 'Ann Example', 'vault contact replaced the duplicate; Bob kept');
    ok(B.store.getSettings().pageSize === 75 && B.store.getSettings().defaultEncrypt === true, 'settings arrived on PC-B');
    ok(B.store.getSettings().appLock.hash === 'PINHASH-B', 'app lock PIN stays per-PC');

    st = await A.sync.sync();
    ok(A.contacts.list.some(c => c.name === 'Bob'), 'Bob (from PC-B) arrived on PC-A');

    /* ---------- settled: another round changes nothing ---------- */
    let a2 = await A.sync.sync(), b2 = await B.sync.sync();
    ok(a2.result.pushed === 0 && a2.result.applied === 0 && b2.result.pushed === 0 && b2.result.applied === 0, 'in sync: nothing more to send either way');

    /* ---------- edit, delete ---------- */
    B.contacts.save({ ...B.contacts.get(ann.id), notes: 'new phone 555' });
    await B.sync.sync(); await A.sync.sync();
    ok(A.contacts.get(ann.id).notes === 'new phone 555', 'edit on PC-B reached PC-A');
    const bob = A.contacts.byEmail('bob@b.test');
    A.contacts.delete(bob.id);
    await A.sync.sync(); await B.sync.sync();
    ok(!B.contacts.byEmail('bob@b.test'), 'deletion on PC-A reached PC-B');

    /* ---------- conflict: both edit; newer edit wins, then settles ---------- */
    A.contacts.save({ ...A.contacts.get(ann.id), notes: 'edit from A' });
    A.sync.noteLocalChange();
    await new Promise(r => setTimeout(r, 30));
    B.contacts.save({ ...B.contacts.get(ann.id), notes: 'edit from B (newer)' });
    B.sync.noteLocalChange();
    await A.sync.sync();             // A uploads first
    const bc = await B.sync.sync();  // B: conflict — B's edit is newer, B wins
    ok(bc.result.conflicts === 1, 'conflict detected');
    await A.sync.sync();
    ok(A.contacts.get(ann.id).notes === 'edit from B (newer)' && B.contacts.get(ann.id).notes === 'edit from B (newer)', 'newer edit won on both PCs');
    a2 = await A.sync.sync(); b2 = await B.sync.sync();
    ok(a2.result.pushed + b2.result.pushed + a2.result.applied + b2.result.applied === 0, 'settled after the conflict');

    /* ---------- key changed on one PC (expiry extended) merges to the other ---------- */
    await A.pgp.extendExpiry(myKey.fingerprint, 'key-pass-123', 5);
    await A.sync.sync(); await B.sync.sync();
    ok(B.pgp.privateKeys.get(myKey.fingerprint).armor() === A.pgp.privateKeys.get(myKey.fingerprint).armor(), 'extended key arrived on PC-B');

    /* ---------- account deleted on B; a secret key deleted on B is parked on A ---------- */
    const other = await B.pgp.generate({ name: 'Test', email: 'test@x.test', passphrase: 'key-pass-456' });
    await B.sync.sync(); await A.sync.sync();
    ok(A.pgp.privateKeys.has(other.fingerprint), 'new key from PC-B arrived on PC-A');
    B.pgp.deleteKey(other.fingerprint, { includePrivate: true });
    await B.sync.sync(); await A.sync.sync();
    const parked = fs.existsSync(path.join(A.dir, 'keyring', 'removed-by-sync')) ? fs.readdirSync(path.join(A.dir, 'keyring', 'removed-by-sync')) : [];
    ok(!A.pgp.publicKeys.has(other.fingerprint) && parked.some(f => f.startsWith(other.fingerprint) && f.endsWith('.asc')), 'secret key deleted elsewhere is parked, not destroyed');

    /* ---------- passphrase change on A: B must enter the new one ---------- */
    await assert.rejects(A.sync.changePassphrase({ current: 'wrong wrong wrong', next: 'vault passphrase 2' }), /not correct/);
    await A.sync.changePassphrase({ current: 'vault passphrase 1', next: 'vault passphrase 2' });
    B.contacts.save({ name: 'Carol', emails: ['carol@c.test'] });
    st = await B.sync.sync();
    ok(st.needs === 'passphrase', 'PC-B notices the passphrase change');
    await assert.rejects(B.sync.reauth('vault passphrase 1'), /isn't the vault passphrase/);
    st = await B.sync.reauth('vault passphrase 2');
    ok(!st.needs && !st.result.error, 'PC-B unlocked with the new passphrase');
    await A.sync.sync();
    ok(!!A.contacts.byEmail('carol@c.test'), 'sync works again after the change');

    /* ---------- devices + sign out ---------- */
    const devs = await A.sync.devices();
    ok(devs.length === 2 && devs.some(d => d.current && d.name === 'PC-A'), 'device list');
    await A.sync.revoke(devs.find(d => !d.current).id);
    st = await B.sync.sync();
    ok(st.needs === 'signin', 'signed-out PC-B is told to sign in again');
    st = await B.sync.reauth('vault passphrase 2');
    ok(!st.needs && !st.result.error, 'PC-B signed in again');

    /* ---------- rate limit on wrong passphrases ---------- */
    const C = await device(root, 'C');
    let limited = false;
    for (let i = 0; i < 7; i++) {
      try { await C.sync.connect({ server: url, username: 'jeff', passphrase: 'guess number ' + i, deviceName: 'X' }); }
      catch (e) { if (/Too many wrong attempts/.test(e.message)) { limited = true; break; } }
    }
    ok(limited, 'repeated wrong passphrases are locked out');

    /* ---------- disconnect keeps local data ---------- */
    await B.sync.disconnect();
    ok(!B.sync.connected() && B.contacts.list.length > 0 && !fs.existsSync(path.join(B.dir, 'sync.json')), 'disconnect forgets sync, keeps data');

    console.log(`\nv140 sync tests: ${passed} passed`);
  } finally {
    php.kill();
  }
})().catch(e => { console.error('FAILED:', e); process.exit(1); });
