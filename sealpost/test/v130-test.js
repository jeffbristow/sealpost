/* Sealpost 1.3.0 self-test: PIN-encrypted offline cache. Run with `npm test`. */
const os = require('os');
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const openpgp = require('openpgp');
const { CacheStore } = require('../src/main/cache');
const { PgpEngine } = require('../src/main/pgp');

(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sealpost-130-'));
  const pgp = new PgpEngine(tmp); await pgp.load();
  const me = await pgp.generate({ name: 'Me', email: 'me@x.test', passphrase: 'key-pass-123' });

  const cache = new CacheStore(tmp);
  let t = Date.now();
  await cache.create('48151623', pgp);
  const createMs = Date.now() - t;

  // a plain-text message and a PGP-encrypted one
  const plain = Buffer.from('From: a@b.test\r\nSubject: Quarterly numbers\r\n\r\nThe secret budget is 42 million.\r\n');
  const armored = await openpgp.encrypt({ message: await openpgp.createMessage({ text: 'pgp body' }), encryptionKeys: pgp.publicKeys.get(me.fingerprint), format: 'armored' });
  const encMsg = Buffer.from('From: a@b.test\r\nSubject: x\r\nContent-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary=B\r\n\r\n--B\r\n\r\n' + armored + '\r\n--B--\r\n');

  cache.saveFolders('acc1', [{ path: 'INBOX', name: 'Inbox' }, { path: 'Projects/Secret Plans', name: 'Secret Plans' }]);
  cache.upsertSummaries('acc1', 'INBOX', [
    { uid: 1, subject: 'Quarterly numbers', from: [{ name: 'Ann', address: 'a@b.test' }], to: [], date: '2026-10-01T10:00:00Z', seen: false },
    { uid: 2, subject: 'x', from: [{ name: '', address: 'a@b.test' }], to: [], date: '2026-10-02T10:00:00Z', seen: true, encrypted: true }
  ], 777);
  cache.putBody('acc1', 'INBOX', 1, plain);
  cache.putBody('acc1', 'INBOX', 2, encMsg);
  cache.upsertSummaries('acc1', 'Projects/Secret Plans', [{ uid: 5, subject: 'Plan B', from: [], to: [], date: '2026-09-01T00:00:00Z' }], 1);

  /* ---------- nothing readable on disk ---------- */
  const files = [];
  (function walk(d) { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); e.isDirectory() ? walk(p) : files.push(p); } })(path.join(tmp, 'cache'));
  for (const f of files) {
    const b = fs.readFileSync(f, 'latin1');
    for (const s of ['secret budget', 'Quarterly', 'Secret Plans', 'Plan B', 'a@b.test', '48151623']) assert(!b.includes(s), `${path.basename(f)} leaks "${s}"`);
  }
  assert(!files.some(f => /Secret|Projects|INBOX/i.test(f)), 'folder names not visible in file names');
  console.log(`✓ cache encrypted: no message text, subjects, addresses or folder names on disk (${files.length} files; setup took ${createMs} ms)`);

  /* ---------- PGP mail stays PGP-encrypted inside the cache ---------- */
  assert(cache.getBody('acc1', 'INBOX', 2).toString().includes('-----BEGIN PGP MESSAGE-----'));
  console.log('✓ encrypted mail is stored as received (still PGP-encrypted inside the cache)');

  /* ---------- locked: unusable; wrong PIN rejected; right PIN works after restart ---------- */
  cache.lock();
  assert.throws(() => cache.getIndex('acc1', 'INBOX'), /locked/);
  const again = new CacheStore(tmp);                       // like restarting Sealpost
  assert.strictEqual(again.unlockWithPin('48151624'), false);
  t = Date.now();
  assert.strictEqual(again.unlockWithPin('48151623'), true);
  const unlockMs = Date.now() - t;
  assert.strictEqual(again.getBody('acc1', 'INBOX', 1).toString(), plain.toString());
  console.log(`✓ wrong PIN rejected; correct PIN opens the cache after a restart (${unlockMs} ms per attempt)`);

  /* ---------- forgot PIN: a key passphrase opens it ---------- */
  const viaKey = new CacheStore(tmp);
  const dec = await openpgp.decryptKey({ privateKey: pgp.privateKeys.get(me.fingerprint), passphrase: 'key-pass-123' });
  assert(await viaKey.unlockWithPgp([dec]));
  assert(viaKey.getIndex('acc1', 'INBOX').messages[1].subject === 'Quarterly numbers');
  console.log('✓ "Forgot PIN" path: your PGP key opens the cache');

  /* ---------- PIN change keeps the data ---------- */
  again.rewrapPin('99887766');
  const after = new CacheStore(tmp);
  assert(!after.unlockWithPin('48151623'), 'old PIN no longer works');
  assert(after.unlockWithPin('99887766'));
  assert(after.getBody('acc1', 'INBOX', 1));
  console.log('✓ changing the PIN re-locks the cache with the new PIN, data kept');

  /* ---------- offline list + search ---------- */
  const l = after.listMessages('acc1', 'INBOX', { search: 'budget' });
  assert.deepStrictEqual(l.messages.map(m => m.uid), [1], 'body search on saved plain-text mail');
  assert.strictEqual(after.listMessages('acc1', 'INBOX', {}).messages[0].uid, 2, 'newest first');
  after.setFlag('acc1', 'INBOX', 1, '\\Seen', true);
  assert(after.getIndex('acc1', 'INBOX').messages[1].seen);
  console.log('✓ offline list, search (incl. saved message text) and flag changes');

  /* ---------- server rebuilt the folder (UIDVALIDITY changed) ---------- */
  after.upsertSummaries('acc1', 'INBOX', [{ uid: 1, subject: 'new world', date: '2026-10-10T00:00:00Z' }], 778);
  const idx = after.getIndex('acc1', 'INBOX');
  assert.deepStrictEqual(Object.keys(idx.messages), ['1']);
  assert.strictEqual(idx.messages[1].subject, 'new world');
  assert(!after.hasBody('acc1', 'INBOX', 2));
  console.log('✓ folder rebuilt on the server -> its old cache is discarded');

  /* ---------- size cap evicts oldest first ---------- */
  after.saveFolders('acc1', [{ path: 'INBOX' }]);
  for (let i = 10; i < 20; i++) {
    after.putBody('acc1', 'INBOX', i, crypto.randomBytes(50000), { uid: i, subject: 's' + i, date: new Date(2026, 0, i).toISOString() });
  }
  const before = after.usage().bytes;
  const removed = after.enforceCap(before - 200000, ['acc1']);
  const left = Object.keys(after.getIndex('acc1', 'INBOX').bodies).map(Number);
  assert(removed >= 4 && after.usage().bytes <= before - 200000);
  assert(!left.includes(10) && left.includes(19), 'oldest removed, newest kept');
  console.log(`✓ storage cap: removed ${removed} oldest saved messages, newest kept`);

  /* ---------- queues ---------- */
  after.addOutbox({ accId: 'acc1', raw: Buffer.from('raw mime'), envelope: { to: ['x@y.test'] } });
  after.pushQueue('pending', { accId: 'acc1', folder: 'INBOX', uid: 1, flag: '\\Seen', on: true });
  const re = new CacheStore(tmp); re.unlockWithPin('99887766');
  assert.strictEqual(Buffer.from(re.outbox()[0].raw, 'base64').toString(), 'raw mime');
  assert.strictEqual(re.getQueue('pending').length, 1);
  assert(!fs.readFileSync(path.join(tmp, 'cache', 'outbox.bin'), 'latin1').includes('x@y.test'));
  console.log('✓ outbox + pending changes survive a restart, encrypted');

  /* ---------- destroy ---------- */
  re.destroy();
  assert(!fs.existsSync(path.join(tmp, 'cache')));
  console.log('✓ clear cache removes everything\n\nAll 1.3.0 tests passed.');
})().catch(e => { console.error('TEST FAILED:', e); process.exit(1); });

const crypto = require('crypto');
