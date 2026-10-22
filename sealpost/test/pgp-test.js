/* Sealpost — engine self-test: run with `npm test`
 * Generates throwaway keys in a temp folder and round-trips
 * signed / encrypted / signed+encrypted / protected-subject messages. */
const os = require('os');
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const { PgpEngine } = require('../src/main/pgp');
const { composeMessage } = require('../src/main/compose');
const { readMessage } = require('../src/main/reader');

(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sealpost-test-'));
  const alice = new PgpEngine(path.join(tmp, 'alice'));
  const bob = new PgpEngine(path.join(tmp, 'bob'));
  await alice.load(); await bob.load();

  const a = await alice.generate({ name: 'Alice Ä', email: 'alice@example.com', passphrase: 'alice-pass-123' });
  const b = await bob.generate({ name: 'Bob', email: 'bob@example.org', passphrase: 'bob-pass-1234', algorithm: 'ecc' });
  console.log('Generated', a.fingerprintPretty, a.algorithm, '/', b.fingerprintPretty);

  // exchange public keys
  await alice.importKeys(bob.exportPublic(b.fingerprint));
  await bob.importKeys(alice.exportPublic(a.fingerprint));

  const acct = { name: 'Alice Ä', email: 'alice@example.com' };
  const attach = [{ filename: 'notes ü.txt', content: Buffer.from('attached data ✓').toString('base64'), contentType: 'text/plain' }];

  // passphrase prompt path
  try {
    await composeMessage(alice, acct, { to: 'bob@example.org', subject: 'x', text: 'y', sign: true });
    assert.fail('should need passphrase');
  } catch (e) { assert.strictEqual(e.code, 'NEED_PASSPHRASE'); console.log('✓ passphrase required before signing'); }

  try { await alice.unlock(a.fingerprint, 'wrong'); assert.fail(); } catch (e) { assert.match(e.message, /Wrong/); }
  await alice.unlock(a.fingerprint, 'alice-pass-123');
  await bob.unlock(b.fingerprint, 'bob-pass-1234');

  // 1) signed only
  let m = await composeMessage(alice, acct, { to: 'Bob <bob@example.org>', subject: 'Signed héllo', text: 'Line one\nLine two  \n\nSignature test ✓', sign: true, attachments: attach });
  let v = await readMessage(m.raw, bob);
  assert(v.pgp.signed && !v.pgp.encrypted);
  assert(v.pgp.signatures[0].valid, JSON.stringify(v.pgp));
  assert(v.pgp.signatures[0].matchesSender);
  assert.strictEqual(v.subject, 'Signed héllo');
  assert(v.text.includes('Signature test ✓'));
  assert.strictEqual(v.attachments[0].filename, 'notes ü.txt');
  console.log('✓ PGP/MIME signed: valid, attachment ok');

  // tamper -> must fail
  const tampered = Buffer.from(m.raw.toString('binary').replace(/Content-Transfer-Encoding: base64\r\n\r\nTGluZ/, 'Content-Transfer-Encoding: base64\r\n\r\nTGlub'), 'binary');
  v = await readMessage(tampered, bob);
  assert(!v.pgp.signatures[0].valid);
  console.log('✓ tampered signed message detected');

  // 2) signed + encrypted with hidden subject
  m = await composeMessage(alice, acct, { to: 'bob@example.org', subject: 'Secret plans', text: 'Top secret body', sign: true, encrypt: true, hideSubject: true, attachments: attach, attachPublicKey: true });
  assert(!m.raw.toString().includes('Top secret'));
  assert(!m.raw.toString().includes('Secret plans'));
  v = await readMessage(m.raw, bob);
  assert(v.pgp.encrypted && v.pgp.decrypted && v.pgp.signatures[0].valid, JSON.stringify(v.pgp));
  assert.strictEqual(v.subject, 'Secret plans');
  assert(v.text.includes('Top secret body'));
  assert(v.attachments.some(x => x.isKey));
  console.log('✓ PGP/MIME encrypted+signed, protected subject, key attachment');

  // sender can read own Sent copy
  v = await readMessage(m.raw, alice);
  assert(v.pgp.decrypted);
  console.log('✓ encrypt-to-self: sender can read Sent copy');

  // locked key -> NEED_PASSPHRASE surfaced in view
  bob.lockAll();
  v = await readMessage(m.raw, bob);
  assert(v.pgp.needPassphrase && v.pgp.needPassphrase.fingerprint === b.fingerprint);
  console.log('✓ locked key prompts for passphrase');
  await bob.unlock(b.fingerprint, 'bob-pass-1234');

  // 3) missing recipient key
  try { await composeMessage(alice, acct, { to: 'nobody@nowhere.net', subject: 's', text: 't', encrypt: true }); assert.fail(); }
  catch (e) { assert.strictEqual(e.code, 'MISSING_KEYS'); console.log('✓ missing recipient key reported'); }

  // 4) inline cleartext + inline encrypted
  const clear = await alice.signCleartext({ text: 'inline signed text', signerFp: a.fingerprint });
  const r = await bob.verifyCleartext(clear);
  assert(r.signatures[0].valid);
  const armored = await alice.encrypt({ data: Buffer.from('inline secret'), recipients: ['bob@example.org'], signerFp: a.fingerprint });
  const inlineMail = Buffer.from('From: alice@example.com\r\nTo: bob@example.org\r\nSubject: inline\r\nContent-Type: text/plain\r\n\r\nHi\r\n' + armored.replace(/\n/g, '\r\n'));
  v = await readMessage(inlineMail, bob);
  assert(v.pgp.decrypted && v.text.includes('inline secret') && v.pgp.signatures[0].valid);
  console.log('✓ inline PGP decrypt + cleartext verify');

  // 5) change passphrase, revoke
  await alice.changePassphrase(a.fingerprint, 'alice-pass-123', 'new-pass-456');
  await alice.unlock(a.fingerprint, 'new-pass-456');
  const rev = await alice.revoke(a.fingerprint);
  assert(rev.revoked);
  console.log('✓ change passphrase + revoke');

  // 6) reload keyring from disk
  const again = new PgpEngine(path.join(tmp, 'bob'));
  await again.load();
  assert.strictEqual((await again.listKeys()).length, 2);
  console.log('✓ keyring persists on disk');

  // 7) remembered passphrase (1.0.2): auto-unlock without prompting
  const fakeSecure = { encrypt: s => Buffer.from(s).toString('base64').split('').reverse().join(''), decrypt: b => Buffer.from(b.split('').reverse().join(''), 'base64').toString() };
  const carol = new PgpEngine(path.join(tmp, 'carol'), null, fakeSecure); await carol.load();
  const c = await carol.generate({ name: 'Carol', email: 'carol@example.net', passphrase: 'carol-pass-1' });
  await carol.importKeys(bob.exportPublic(b.fingerprint));
  await bob.importKeys(carol.exportPublic(c.fingerprint));
  const toCarol = await composeMessage(bob, { name: 'Bob', email: 'bob@example.org' }, { to: 'carol@example.net', subject: 'auto', text: 'auto unlock works', sign: true, encrypt: true });
  carol.lockAll();
  v = await readMessage(toCarol.raw, carol);
  assert(v.pgp.needPassphrase, 'should still prompt before remembering');
  try { await carol.rememberPassphrase(c.fingerprint, 'nope'); assert.fail(); } catch (e) { assert.match(e.message, /Wrong/); }
  assert(!carol.hasRemembered(c.fingerprint));
  await carol.rememberPassphrase(c.fingerprint, 'carol-pass-1');
  assert(!fs.readFileSync(path.join(tmp, 'carol', 'keyring', 'remembered.json'), 'utf8').includes('carol-pass-1'));
  const carol2 = new PgpEngine(path.join(tmp, 'carol'), null, fakeSecure); await carol2.load(); // simulates app restart
  v = await readMessage(toCarol.raw, carol2);
  assert(v.pgp.decrypted && v.text.includes('auto unlock works'), 'auto-unlock decrypt');
  carol2.lockAll();
  await composeMessage(carol2, { name: 'Carol', email: 'carol@example.net' }, { to: 'bob@example.org', subject: 's', text: 't', sign: true });
  assert((await carol2.describe(carol2.publicKeys.get(c.fingerprint))).passphraseRemembered);
  await carol2.changePassphrase(c.fingerprint, 'carol-pass-1', 'carol-pass-2');
  carol2.lockAll();
  v = await readMessage(toCarol.raw, carol2);
  assert(v.pgp.decrypted, 'remembered passphrase follows a passphrase change');
  carol2.forgetPassphrase(c.fingerprint); carol2.lockAll();
  v = await readMessage(toCarol.raw, carol2);
  assert(v.pgp.needPassphrase, 'prompts again after forget');
  const noSecure = new PgpEngine(path.join(tmp, 'carol')); await noSecure.load();
  assert(!noSecure.canRemember());
  console.log('✓ remembered passphrase: auto-unlock, restart, change, forget');

  // write sample messages for external interop checks
  fs.writeFileSync(path.join(tmp, 'encrypted.eml'), m.raw);
  console.log('\nAll tests passed. Temp dir:', tmp);
})().catch(e => { console.error('TEST FAILED:', e); process.exit(1); });
