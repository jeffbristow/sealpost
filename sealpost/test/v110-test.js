/* Sealpost 1.1.0 self-test: contacts / pinned keys, rich text, drafts, key expiry.
 * Run with `npm test` (runs after pgp-test.js). */
const os = require('os');
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const openpgp = require('openpgp');
const { PgpEngine } = require('../src/main/pgp');
const { ContactStore } = require('../src/main/contacts');
const { composeMessage, buildDraft } = require('../src/main/compose');
const { readMessage, readDraft } = require('../src/main/reader');

(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sealpost-110-'));
  const me = new PgpEngine(path.join(tmp, 'me'));
  const contacts = new ContactStore(path.join(tmp, 'me'));
  me.setPinnedLookup(e => contacts.pinnedFor(e));
  await me.load();
  const mine = await me.generate({ name: 'Me', email: 'me@x.test', passphrase: 'me-pass-123' });
  await me.unlock(mine.fingerprint, 'me-pass-123');
  const acct = { name: 'Me', email: 'me@x.test' };

  // two different keys for the same friend address (e.g. an old and a new/impostor key)
  const friendA = new PgpEngine(path.join(tmp, 'fa')); await friendA.load();
  const fa = await friendA.generate({ name: 'Friend', email: 'friend@y.test', passphrase: 'friend-pass-1' });
  await new Promise(r => setTimeout(r, 1100)); // ensure B is "newer"
  const friendB = new PgpEngine(path.join(tmp, 'fb')); await friendB.load();
  const fb = await friendB.generate({ name: 'Friend', email: 'friend@y.test', passphrase: 'friend-pass-2' });
  await friendA.unlock(fa.fingerprint, 'friend-pass-1');
  await friendB.unlock(fb.fingerprint, 'friend-pass-2');
  await me.importKeys(friendA.exportPublic(fa.fingerprint));
  await friendA.importKeys(me.exportPublic(mine.fingerprint));

  /* ---------- 1. Contacts + pinned keys ---------- */
  const c = contacts.save({ name: 'Friend', emails: ['Friend@Y.test'], keyFp: fa.fingerprint, encrypt: 'always' });
  assert.deepStrictEqual(c.emails, ['friend@y.test']);
  assert.throws(() => contacts.save({ name: 'Dup', emails: ['friend@y.test'] }), /already belongs/);
  assert.strictEqual(contacts.search('fri')[0].email, 'friend@y.test');

  await me.importKeys(friendB.exportPublic(fb.fingerprint)); // newer key appears
  let st = (await me.recipientStatus(['friend@y.test']))['friend@y.test'];
  assert(st.ok && st.pinned && st.fingerprint === fa.fingerprint, 'pinned key used, not the newer one');
  assert.strictEqual(st.otherKey, fb.fingerprint, 'key change detected');

  let m = await composeMessage(me, acct, { to: 'friend@y.test', subject: 's', text: 'pinned!', encrypt: true, sign: true });
  let v = await readMessage(m.raw, friendA);
  assert(v.pgp.decrypted, 'pinned (A) can decrypt');
  v = await readMessage(m.raw, friendB);
  assert(!v.pgp.decrypted, 'newer unpinned key (B) cannot');
  console.log('✓ contact pinned key is used; different key for same address flagged');

  contacts.pinKey(c.id, fb.fingerprint);
  st = (await me.recipientStatus(['friend@y.test']))['friend@y.test'];
  assert(st.fingerprint === fb.fingerprint && st.otherKey === null);
  contacts.pinKey(c.id, 'DEADBEEF'.repeat(5));
  st = (await me.recipientStatus(['friend@y.test']))['friend@y.test'];
  assert(!st.ok && st.problem === 'missing', 'missing pinned key is not silently replaced');
  contacts.pinKey(c.id, fa.fingerprint);
  assert.strictEqual(me.fingerprintForKeyId(fa.keyId), fa.fingerprint);
  console.log('✓ re-pinning, missing pinned key reported');

  /* ---------- 2. Rich text ---------- */
  m = await composeMessage(me, acct, { to: 'friend@y.test', subject: 'rich', html: '<p>Hello <b>bold</b> and <i>italic</i></p><ul><li>one</li></ul>', encrypt: true, sign: true });
  v = await readMessage(m.raw, friendA);
  assert(v.html.includes('<b>bold</b>') && /Hello bold/i.test(v.text) && v.pgp.signatures[0].valid, 'rich + plain alternative, signed+encrypted');
  m = await composeMessage(me, acct, { to: 'friend@y.test', subject: 'rich signed', html: '<p>Signed <u>rich</u></p>', sign: true });
  v = await readMessage(m.raw, friendA);
  assert(v.html.includes('<u>rich</u>') && v.pgp.signatures[0].valid, 'rich signed-only verifies');
  console.log('✓ rich text: HTML + plain-text versions, signed and encrypted');

  /* ---------- 3. Drafts ---------- */
  const draft = {
    to: 'Friend <friend@y.test>', cc: 'x@z.test', bcc: 'secret@b.test', subject: 'Plans ü', html: '<p>Draft <b>body</b></p>',
    encrypt: true, sign: false, hideSubject: true, inReplyTo: '<abc@x>',
    attachments: [{ filename: 'n.txt', content: Buffer.from('attached').toString('base64'), contentType: 'text/plain' }]
  };
  const d = await buildDraft(me, acct, draft);
  const rawStr = d.raw.toString();
  assert(d.encrypted && !rawStr.includes('Plans') && !rawStr.includes('friend@y.test') && !rawStr.includes('secret@b.test'), 'nothing readable on server');
  me.lockAll();
  try { await readDraft(d.raw, me); assert.fail(); } catch (e) { assert.strictEqual(e.code, 'NEED_PASSPHRASE'); }
  await me.unlock(mine.fingerprint, 'me-pass-123');
  const back = await readDraft(d.raw, me);
  assert.strictEqual(back.subject, 'Plans ü');
  assert(back.to.includes('friend@y.test') && back.cc.includes('x@z.test') && back.bcc.includes('secret@b.test'));
  assert(back.html.includes('<b>body</b>') && back.meta.encrypt === true && back.meta.hideSubject === true && back.meta.inReplyTo === '<abc@x>');
  assert.strictEqual(Buffer.from(back.attachments[0].content, 'base64').toString(), 'attached');
  // reopened draft can be sent as-is
  m = await composeMessage(me, acct, { ...back, cc: '', bcc: '', sign: true, encrypt: true, attachments: back.attachments });
  v = await readMessage(m.raw, friendA);
  assert(v.pgp.decrypted && v.attachments.some(a => a.filename === 'n.txt'));
  // no own key -> plain draft
  const nokey = new PgpEngine(path.join(tmp, 'nokey')); await nokey.load();
  const pd = await buildDraft(nokey, { email: 'nk@x.test' }, { to: 'a@b.test', subject: 'plain draft', text: 'hello' });
  assert(!pd.encrypted);
  const pback = await readDraft(pd.raw, nokey);
  assert(pback.subject === 'plain draft' && pback.to.includes('a@b.test') && pback.text.includes('hello'));
  assert.strictEqual((pd.raw.toString().match(/^To:/gm) || []).length, 1, 'no duplicate To header');
  console.log('✓ drafts: encrypted to self, round-trip with attachments + settings, plain fallback');

  /* ---------- 4. Expiry warnings + extend ---------- */
  const { privateKey } = await openpgp.generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Soon', email: 'soon@x.test' }], passphrase: 'soon-pass-1', keyExpirationTime: 10 * 86400, format: 'armored' });
  await me.importKeys(privateKey);
  const soonFp = (await me.listKeys()).find(k => k.emails.includes('soon@x.test')).fingerprint;
  let w = await me.expiryWarnings(30);
  assert(w.some(x => x.fingerprint === soonFp && x.daysLeft <= 10 && !x.expired), 'warning for key expiring in 10 days');
  assert(!w.some(x => x.fingerprint === mine.fingerprint), 'no warning for 2-year key');
  try { await me.extendExpiry(soonFp, 'wrong', 2); assert.fail(); } catch (e) { assert.match(e.message, /Wrong/); }
  const ext = await me.extendExpiry(soonFp, 'soon-pass-1', 2);
  assert.strictEqual(ext.fingerprint, soonFp, 'same fingerprint');
  assert(new Date(ext.expires) > new Date(Date.now() + 700 * 86400000), 'new expiry ~2 years');
  w = await me.expiryWarnings(30);
  assert(!w.some(x => x.fingerprint === soonFp));
  const reloaded = new PgpEngine(path.join(tmp, 'me')); await reloaded.load();
  await reloaded.unlock(soonFp, 'soon-pass-1'); // still protected by the same passphrase
  const never = await reloaded.extendExpiry(soonFp, 'soon-pass-1', 0);
  assert.strictEqual(never.expires, null, 'never expires');
  fs.writeFileSync(path.join(tmp, 'extended-public.asc'), reloaded.exportPublic(soonFp));
  console.log('✓ expiry: 30-day warning, extend keeps fingerprint + passphrase, "never" option');

  contacts.forgetKey(fa.fingerprint);
  assert.strictEqual(contacts.get(c.id).keyFp, null);
  console.log('\nAll 1.1.0 tests passed. Temp dir:', tmp);
})().catch(e => { console.error('TEST FAILED:', e); process.exit(1); });
