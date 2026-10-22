/* Sealpost 1.5.0 self-test: "Remember passphrase on all my devices".
 * Needs `php` on the PATH (skipped otherwise). */
const os = require('os');
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const openpgp = require('openpgp');
const { spawn, spawnSync } = require('child_process');
const { Store } = require('../src/main/store');
const { PgpEngine } = require('../src/main/pgp');
const { ContactStore } = require('../src/main/contacts');
const { SyncService } = require('../src/main/sync');

const SERVER_SRC = process.env.SEALPOST_SERVER || path.join(__dirname, '..', '..', 'sealpost-web', 'server');
const PORT = 8890 + Math.floor(Math.random() * 100);
let passed = 0;
const ok = (c, m) => { assert(c, m); passed++; console.log('  ✓', m); };

async function device(root, name) {
  const dir = path.join(root, name); fs.mkdirSync(dir, { recursive: true });
  const store = new Store(dir), pgp = new PgpEngine(dir); await pgp.load();
  const contacts = new ContactStore(dir);
  return { dir, store, pgp, contacts, sync: new SyncService({ dataDir: dir, store, pgp, contacts }) };
}

(async () => {
  if (spawnSync('php', ['-v']).status !== 0 || !fs.existsSync(SERVER_SRC)) { console.log('v150: php or server files not found — test skipped'); return; }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sealpost-150-'));
  fs.cpSync(SERVER_SRC, path.join(root, 'www'), { recursive: true });
  // a fresh clone has only the template (the real config.php isn't in git)
  if (!fs.existsSync(path.join(root, 'www', 'config.php'))) fs.copyFileSync(path.join(root, 'www', 'config.example.php'), path.join(root, 'www', 'config.php'));
  const php = spawn('php', ['-S', '127.0.0.1:' + PORT, '-t', path.join(root, 'www')], { stdio: 'ignore' });
  const url = `http://127.0.0.1:${PORT}/`;
  try {
    for (let i = 0; i < 50; i++) { try { await fetch(url + 'api.php?action=ping'); break; } catch { await new Promise(r => setTimeout(r, 100)); } }
    const setupCode = fs.readFileSync(path.join(root, 'www', 'config.php'), 'utf8').match(/'setup_code'\s*=>\s*'([^']+)'/)[1];
    const A = await device(root, 'A'), B = await device(root, 'B');
    const k = await A.pgp.generate({ name: 'Me', email: 'me@x.test', passphrase: 'key-pass-123' });
    await A.sync.connect({ server: url, username: 'meme', passphrase: 'vault passphrase 1', create: true, setupCode });
    await B.sync.connect({ server: url, username: 'meme', passphrase: 'vault passphrase 1' });
    const msg = await openpgp.encrypt({ message: await openpgp.createMessage({ text: 'secret' }), encryptionKeys: A.pgp.publicKeys.get(k.fingerprint) });

    await assert.rejects(B.pgp.decrypt(msg), e => e.code === 'NEED_PASSPHRASE');
    ok(true, 'PC-B asks for the passphrase before');
    await assert.rejects(A.pgp.syncPassphrase(k.fingerprint, 'wrong'), /Wrong passphrase/);
    ok(true, 'wrong passphrase is not stored');
    await A.pgp.syncPassphrase(k.fingerprint, 'key-pass-123');
    A.pgp.lockAll();
    ok((await A.pgp.describe(A.pgp.privateKeys.get(k.fingerprint))).passphraseSynced, 'key shows "all devices"');
    await A.sync.sync(); await B.sync.sync();
    ok((await B.pgp.decrypt(msg)).data.toString() === 'secret', 'PC-B decrypts without asking');

    // passphrase change on A follows to B
    await A.pgp.changePassphrase(k.fingerprint, 'key-pass-123', 'key-pass-456');
    await A.sync.sync(); await B.sync.sync();
    B.pgp.lockAll();
    ok((await B.pgp.decrypt(msg)).data.toString() === 'secret', 'changed key passphrase follows to PC-B');
    ok(B.pgp.getSyncedPassphrase(k.fingerprint) === 'key-pass-456', 'PC-B holds the new passphrase');

    // turn off
    A.pgp.clearSyncedPassphrase(k.fingerprint);
    await A.sync.sync(); await B.sync.sync();
    B.pgp.lockAll();
    await assert.rejects(B.pgp.decrypt(msg), e => e.code === 'NEED_PASSPHRASE');
    ok(!B.pgp.hasSyncedPassphrase(k.fingerprint), 'turning it off removes it from PC-B');
    const a2 = await A.sync.sync(), b2 = await B.sync.sync();
    ok(a2.result.pushed + b2.result.pushed === 0, 'settled');
    console.log(`\nv150 tests: ${passed} passed`);
  } finally { php.kill(); }
})().catch(e => { console.error('FAILED:', e); process.exit(1); });
