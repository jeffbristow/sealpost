/* Sealpost 1.9.0 self-test: "Send as" addresses (account aliases). */
const os = require('os');
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const { simpleParser } = require('mailparser');
const { Store } = require('../src/main/store');
const { PgpEngine } = require('../src/main/pgp');
const { composeMessage, buildDraft, senderFor } = require('../src/main/compose');
const { readMessage, readDraft } = require('../src/main/reader');

let passed = 0;
const ok = (c, m) => { assert(c, m); passed++; console.log('  ✓', m); };

(async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sealpost-190-'));

  // ---- 1. store keeps a tidy "Send as" list ----
  const store = new Store(path.join(root, 's'));
  const saved = store.saveAccount({
    email: 'jeff@thebristows.com', name: 'Jeff', imapHost: 'imap.x', smtpHost: 'smtp.x', password: 'p',
    aliases: [{ email: 'jeff@alias.example', name: 'Jeff Bristow' }, { email: 'JEFF@alias.example' }, { email: 'jeff@thebristows.com' }, { email: 'not an address' }]
  });
  const acc = store.getAccount(saved.id || store.data.accounts[0].id);
  ok(acc.aliases.length === 1 && acc.aliases[0].email === 'jeff@alias.example', 'aliases cleaned: duplicates, own address and junk removed');
  const { aliases: _drop, ...older } = store.data.accounts[0];
  store.saveAccount({ ...older, password: '' });
  ok(store.getAccount(acc.id).aliases.length === 1, 'aliases kept when an older device saves the account without them');

  // ---- 2. senderFor ----
  ok(senderFor(acc, 'jeff@alias.example').address === 'jeff@alias.example', 'senderFor picks the alias');
  ok(senderFor(acc, 'JEFF@ALIAS.EXAMPLE').name === 'Jeff Bristow', 'alias match ignores case, uses alias name');
  ok(senderFor(acc, 'evil@elsewhere.test').address === 'jeff@thebristows.com', 'unknown From address falls back to the account');
  ok(senderFor(acc, null).address === 'jeff@thebristows.com', 'no choice = account address');

  // ---- 3. sending as the alias ----
  const me = new PgpEngine(path.join(root, 'me')); await me.load();
  const bob = new PgpEngine(path.join(root, 'bob')); await bob.load();
  const k = await me.generate({ name: 'Jeff', email: 'jeff@thebristows.com', passphrase: 'jeff-pass-123' });
  const b = await bob.generate({ name: 'Bob', email: 'bob@example.org', passphrase: 'bob-pass-1234' });
  await me.unlock(k.fingerprint, 'jeff-pass-123');
  await bob.unlock(b.fingerprint, 'bob-pass-1234');
  await me.importKeys(bob.exportPublic(b.fingerprint));
  await bob.importKeys(me.exportPublic(k.fingerprint));

  let m = await composeMessage(me, acc, { to: 'bob@example.org', subject: 'Hi', text: 'from the alias', sign: true, fromAddress: 'jeff@alias.example' });
  const parsed = await simpleParser(m.raw);
  ok(parsed.from.value[0].address === 'jeff@alias.example' && parsed.from.value[0].name === 'Jeff Bristow', 'From header is the alias');
  ok(m.envelope.from === 'jeff@alias.example', 'SMTP envelope sender is the alias');
  const v = await readMessage(m.raw, bob);
  ok(v.pgp.signatures.some(s => s.valid), 'alias without its own key: signed with the account key, signature valid');

  m = await composeMessage(me, acc, { to: 'bob@example.org', subject: 'Secret', text: 'encrypted from alias', sign: true, encrypt: true, fromAddress: 'jeff@alias.example' });
  const v2 = await readMessage(m.raw, bob);
  ok(v2.pgp.encrypted && /encrypted from alias/.test(v2.text), 'encrypted + signed as the alias, Bob can read it');

  // alias with its own key is preferred
  const k2 = await me.generate({ name: 'Jeff Bristow', email: 'jeff@alias.example', passphrase: 'alias-pass-1' });
  await me.unlock(k2.fingerprint, 'alias-pass-1');
  await bob.importKeys(me.exportPublic(k2.fingerprint));
  m = await composeMessage(me, acc, { to: 'bob@example.org', subject: 'k2', text: 'own key', sign: true, fromAddress: 'jeff@alias.example' });
  const v3 = await readMessage(m.raw, bob);
  ok(v3.pgp.signatures.some(s => s.valid && s.fingerprint === k2.fingerprint), 'alias with its own key signs with that key');

  // ---- 4. drafts remember the alias ----
  const d = await buildDraft(me, acc, { to: 'bob@example.org', subject: 'draft', text: 'later', fromAddress: 'jeff@alias.example' });
  const back = await readDraft(d.raw, me);
  ok(back.meta.fromAddress === 'jeff@alias.example', 'draft reopens with the alias');
  const d2 = await buildDraft(me, acc, { to: 'bob@example.org', subject: 'draft', text: 'later' });
  ok((await readDraft(d2.raw, me)).meta.fromAddress === null, 'draft from the account address has no alias');

  console.log(`\nv190 tests: ${passed} passed`);
})().catch(e => { console.error('FAILED:', e); process.exit(1); });
