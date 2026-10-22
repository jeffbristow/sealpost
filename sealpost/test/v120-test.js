/* Sealpost 1.2.0 self-test: one-file backup + restore. Run with `npm test`. */
const os = require('os');
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const { Store } = require('../src/main/store');
const { PgpEngine } = require('../src/main/pgp');
const { ContactStore } = require('../src/main/contacts');
const { createBackup, readBackup, restoreBackup } = require('../src/main/backup');

// two different fake "Windows logins" — passwords protected on PC A can't be read on PC B
const fakeSecure = tag => ({
  encrypt: s => tag + ':' + Buffer.from(s).toString('base64'),
  decrypt: b => { if (!b.startsWith(tag + ':')) throw new Error('other user'); return Buffer.from(b.slice(tag.length + 1), 'base64').toString(); }
});

async function setup(dir, tag) {
  const store = new Store(dir, fakeSecure(tag));
  const pgp = new PgpEngine(dir, () => store.getSettings(), fakeSecure(tag));
  const contacts = new ContactStore(dir);
  pgp.setPinnedLookup(e => contacts.pinnedFor(e));
  await pgp.load();
  return { store, pgp, contacts };
}

(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sealpost-120-'));

  /* ---------- PC A: a configured Sealpost ---------- */
  const A = await setup(path.join(tmp, 'pcA'), 'A');
  A.store.saveAccount({ name: 'Jeff', email: 'jeff@example.com', username: 'jeff@example.com', password: 'imap-secret-ü', imapHost: 'imap.example.com', smtpHost: 'smtp.example.com', smtpPassword: 'smtp-secret' });
  A.store.setSettings({ composeFormat: 'rich', defaultEncrypt: true, appLock: { enabled: true, salt: 'aa', hash: 'bb', hello: false, idleMinutes: 15 } });
  const mine = await A.pgp.generate({ name: 'Jeff', email: 'jeff@example.com', passphrase: 'my-key-pass-1' });
  const F = new PgpEngine(path.join(tmp, 'friend')); await F.load();
  const fk = await F.generate({ name: 'Friend', email: 'friend@x.test', passphrase: 'friend-pass-1' });
  await A.pgp.importKeys(F.exportPublic(fk.fingerprint));
  A.pgp.setTrust(fk.fingerprint, 'verified');
  A.contacts.save({ name: 'Friend', emails: ['friend@x.test'], keyFp: fk.fingerprint, encrypt: 'always', notes: 'met at conf' });
  A.contacts.save({ name: 'No Key', emails: ['nokey@x.test'] });

  /* ---------- create ---------- */
  await assert.rejects(createBackup({ ...A, appVersion: '1.2.0', passphrase: 'short' }), /at least 10/);
  const { data, summary } = await createBackup({ ...A, appVersion: '1.2.0', passphrase: 'correct horse battery' });
  const file = path.join(tmp, 'Sealpost-backup.sealbackup');
  fs.writeFileSync(file, data);
  const raw = data.toString('latin1');
  for (const secret of ['imap-secret', 'smtp-secret', 'jeff@example.com', 'friend@x.test', 'BEGIN PGP']) assert(!raw.includes(secret), 'backup leaks: ' + secret);
  assert.deepStrictEqual(summary.accounts, ['jeff@example.com']);
  assert.strictEqual(summary.secretKeys, 1);
  assert.strictEqual(summary.contacts, 2);
  console.log('✓ backup created: everything encrypted, nothing readable in the file');

  /* ---------- read ---------- */
  await assert.rejects(readBackup(fs.readFileSync(file), 'wrong passphrase!'), /Wrong backup passphrase/);
  const tampered = Buffer.from(fs.readFileSync(file)); tampered[tampered.length - 30] ^= 0xff;
  await assert.rejects(readBackup(tampered, 'correct horse battery'), /damaged|modified|Wrong/);
  await assert.rejects(readBackup(Buffer.from('hello world'), 'x'), /not a Sealpost backup/);
  const payload = await readBackup(fs.readFileSync(file), 'correct horse battery');
  console.log('✓ wrong passphrase, damaged file and non-backup file are all rejected');

  /* ---------- PC B: fresh install, different Windows login ---------- */
  const B = await setup(path.join(tmp, 'pcB'), 'B');
  const r = await restoreBackup(payload, B, { restoreSettings: true });
  assert.deepStrictEqual(r.accountsAdded, ['jeff@example.com']);
  assert.strictEqual(r.secretKeys, 1);
  assert.strictEqual(r.contactsAdded, 2);
  assert.strictEqual(r.errors.length, 0, r.errors.join('; '));
  const acc = B.store.getAccount(B.store.listAccounts()[0].id);
  assert.strictEqual(acc.password, 'imap-secret-ü');
  assert.strictEqual(acc.smtpPassword, 'smtp-secret');
  assert(JSON.parse(fs.readFileSync(path.join(tmp, 'pcB', 'sealpost.json'), 'utf8')).accounts[0].password.startsWith('enc:B:'), 'password re-protected with the new PC login');
  assert.strictEqual(B.store.getSettings().composeFormat, 'rich');
  assert.strictEqual(B.store.getSettings().appLock.hash, 'bb');
  console.log('✓ restore on a new PC: account passwords, settings and app lock come back');

  // keys: secret key still passphrase-protected and usable; revocation cert and trust restored
  assert(B.pgp.privateKeys.has(mine.fingerprint));
  assert(!B.pgp.privateKeys.get(mine.fingerprint).isDecrypted(), 'secret key still protected');
  await assert.rejects(B.pgp.unlock(mine.fingerprint, 'nope'), /Wrong/);
  await B.pgp.unlock(mine.fingerprint, 'my-key-pass-1');
  assert(fs.existsSync(path.join(tmp, 'pcB', 'keyring', 'private', mine.fingerprint + '.rev')));
  assert.strictEqual(B.pgp.meta[fk.fingerprint].trust, 'verified');
  // contacts: pinned key + rules survive, encryption to the contact works
  const c = B.contacts.byEmail('friend@x.test');
  assert(c.keyFp === fk.fingerprint && c.encrypt === 'always' && c.notes === 'met at conf');
  const st = await B.pgp.recipientStatus(['friend@x.test']);
  assert(st['friend@x.test'].ok && st['friend@x.test'].pinned);
  console.log('✓ keys (still passphrase-protected), revocation cert, trust and contacts restored');

  /* ---------- restoring again merges without duplicates ---------- */
  const r2 = await restoreBackup(payload, B, { restoreSettings: false });
  assert.deepStrictEqual(r2.accountsAdded, []);
  assert.deepStrictEqual(r2.accountsSkipped, ['jeff@example.com']);
  assert.strictEqual(r2.contactsAdded, 0);
  assert.strictEqual(B.store.listAccounts().length, 1);
  assert.strictEqual(B.contacts.all().length, 2);
  console.log('✓ restoring twice merges — no duplicates, nothing deleted');

  fs.writeFileSync(path.join(tmp, 'backup-path.txt'), file);
  console.log('\nAll 1.2.0 tests passed. Backup file:', file);
})().catch(e => { console.error('TEST FAILED:', e); process.exit(1); });
