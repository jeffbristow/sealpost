/* Dev fixture: Jeff + Ann keys, test mails in Dovecot, vault on local PHP server. */
const R = '/home/claude/sealpost/src/main/';
const fs = require('fs'), path = require('path');
const { Store } = require(R + 'store'), { PgpEngine } = require(R + 'pgp'), { ContactStore } = require(R + 'contacts'), { SyncService } = require(R + 'sync');
const { composeMessage } = require(R + 'compose');
const mime = require(R + 'mime');
const openpgp = require('/home/claude/sealpost/node_modules/openpgp');
const { ImapFlow } = require('/home/claude/sealpost/node_modules/imapflow');
const [, , work, serverUrl] = process.argv;

(async () => {
  fs.rmSync(work, { recursive: true, force: true });
  const jdir = path.join(work, 'jeff'), adir = path.join(work, 'ann');
  fs.mkdirSync(jdir, { recursive: true }); fs.mkdirSync(adir, { recursive: true });
  const jp = new PgpEngine(jdir); await jp.load();
  const ap = new PgpEngine(adir); await ap.load();
  const jk = await jp.generate({ name: 'Jeff Test', email: 'jeff@test.local', passphrase: 'key-pass-123' });
  const ak = await ap.generate({ name: 'Ann Example', email: 'ann@friend.test', passphrase: 'ann-pass-123' });
  await ap.importKeys(jp.exportPublic(jk.fingerprint));
  await jp.importKeys(ap.exportPublic(ak.fingerprint));
  await ap.unlock(ak.fingerprint, 'ann-pass-123');
  const annAcc = { name: 'Ann Example', email: 'ann@friend.test' };
  const msgs = [];
  const D = s => new Date(Date.now() - s * 3600e3).toUTCString();
  const plain = (subject, body, from = 'Bob Plain <bob@plain.test>', extra = '') =>
    `From: ${from}\r\nTo: jeff@test.local\r\nSubject: ${subject}\r\nDate: ${D(1)}\r\nMessage-ID: <${Math.random()}@t>\r\nMIME-Version: 1.0\r\n${extra}Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n${body}\r\n`;

  // fillers for paging
  for (let i = 1; i <= 60; i++) msgs.push(['INBOX', plain(`Newsletter #${i}`, `Filler message number ${i}.\nhttps://example.com/item/${i}`), i < 50 ? ['\\Seen'] : []]);
  // non-ascii subject (RFC 2047)
  msgs.push(['INBOX', plain('=?UTF-8?B?' + Buffer.from('Grüße aus Köln ☀').toString('base64') + '?=', 'Hallo Jeff,\nviele Grüße aus Köln!\n\n> quoted line\n\nBob'), []]);
  // HTML with inline cid image, remote image, attachment
  const png = require('fs').readFileSync('/home/claude/sealpost/build/icon-src/../icon.png');
  const html = `<html><body><h2 style="color:#2a7">Quarterly report</h2><p>Hello <b>Jeff</b>, see the chart:</p><p><img src="cid:chart1" width="64" height="64"></p><p>Tracking pixel: <img src="https://tracker.example.com/pixel.gif" width="1" height="1"></p><p><a href="https://example.com/report">Open the full report</a></p><script>alert(1)</script></body></html>`;
  const b = 'BND1', b2 = 'BND2';
  msgs.push(['INBOX', `From: Carol HTML <carol@html.test>\r\nTo: jeff@test.local\r\nSubject: Quarterly report (HTML)\r\nDate: ${D(0.5)}\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="${b}"\r\n\r\n--${b}\r\nContent-Type: multipart/related; boundary="${b2}"\r\n\r\n--${b2}\r\nContent-Type: text/html; charset=utf-8\r\n\r\n${html}\r\n--${b2}\r\nContent-Type: image/png\r\nContent-ID: <chart1>\r\nContent-Disposition: inline\r\nContent-Transfer-Encoding: base64\r\n\r\n${png.toString('base64')}\r\n--${b2}--\r\n--${b}\r\nContent-Type: text/csv; name="numbers.csv"\r\nContent-Disposition: attachment; filename="numbers.csv"\r\n\r\nq,value\r\nQ1,10\r\nQ2,20\r\n--${b}--\r\n`, []]);
  // PGP/MIME encrypted + signed, hidden subject, with attachment
  let m = await composeMessage(ap, annAcc, { to: 'jeff@test.local', subject: 'Secret plans for Friday', text: 'Hi Jeff,\n\nThe meeting moves to Friday 10:00. Bring the blue folder.\n\nAnn', encrypt: true, sign: true, hideSubject: true, attachments: [{ filename: 'agenda.txt', content: Buffer.from('1. Budget\n2. Launch\n').toString('base64'), contentType: 'text/plain' }] });
  msgs.push(['INBOX', m.raw.toString('binary'), []]);
  // PGP/MIME signed only
  m = await composeMessage(ap, annAcc, { to: 'jeff@test.local', subject: 'Signed note from Ann', text: 'This message is signed, not encrypted.\nCheck the signature.', sign: true });
  msgs.push(['INBOX', m.raw.toString('binary'), []]);
  // inline PGP encrypted
  const inl = await openpgp.encrypt({ message: await openpgp.createMessage({ text: 'Inline secret: the code is 4711.' }), encryptionKeys: ap.publicKeys.get(jk.fingerprint), signingKeys: ap.unlocked.get(ak.fingerprint).key, format: 'armored' });
  msgs.push(['INBOX', plain('Old-style inline PGP', inl, 'Ann Example <ann@friend.test>'), []]);
  // inline cleartext signed
  const cs = await openpgp.sign({ message: await openpgp.createCleartextMessage({ text: 'I agree to the terms.\n-- Ann' }), signingKeys: ap.unlocked.get(ak.fingerprint).key });
  msgs.push(['INBOX', plain('Cleartext signed agreement', cs, 'Ann Example <ann@friend.test>'), []]);
  // tampered signed message
  m = await composeMessage(ap, annAcc, { to: 'jeff@test.local', subject: 'Tampered signed mail', text: 'Pay 100 dollars.', sign: true });
  msgs.push(['INBOX', m.raw.toString('binary').replace('UGF5IDEwMCBkb2xsYXJzLg', 'UGF5IDkwMCBkb2xsYXJzLg'), ['\\Flagged']]);
  // encrypted attachment + key attachment in a normal mail
  const encFile = await openpgp.encrypt({ message: await openpgp.createMessage({ binary: Buffer.from('Top secret file contents\n') }), encryptionKeys: ap.publicKeys.get(jk.fingerprint), format: 'binary' });
  msgs.push(['INBOX', `From: Ann Example <ann@friend.test>\r\nTo: jeff@test.local\r\nSubject: File for you + my key\r\nDate: ${D(0.2)}\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="${b}"\r\n\r\n--${b}\r\nContent-Type: text/plain\r\n\r\nEncrypted file attached, plus my public key.\r\n--${b}\r\nContent-Type: application/octet-stream; name="secret.txt.gpg"\r\nContent-Disposition: attachment; filename="secret.txt.gpg"\r\nContent-Transfer-Encoding: base64\r\n\r\n${Buffer.from(encFile).toString('base64')}\r\n--${b}\r\nContent-Type: application/pgp-keys; name="ann.asc"\r\nContent-Disposition: attachment; filename="ann.asc"\r\n\r\n${ap.exportPublic(ak.fingerprint)}\r\n--${b}--\r\n`, []]);
  // a message for a key we don't have
  const stranger = await openpgp.generateKey({ userIDs: [{ email: 'x@y.test' }], format: 'object' });
  const forOther = await openpgp.encrypt({ message: await openpgp.createMessage({ text: 'nope' }), encryptionKeys: stranger.publicKey });
  msgs.push(['INBOX', `From: Zed <zed@z.test>\r\nTo: other@test.local\r\nSubject: Encrypted to someone else\r\nDate: ${D(0.1)}\r\nMIME-Version: 1.0\r\n` + mime.buildEncryptedEntity(forOther) + '\r\n', []]);
  // subfolder with non-ascii name
  msgs.push(['Projekte/Größe', plain('In a subfolder', 'Folder test', 'Dora <dora@d.test>'), []]);

  const client = new ImapFlow({ host: '127.0.0.1', port: 11993, secure: true, tls: { rejectUnauthorized: false }, auth: { user: 'jeff@test.local', pass: 'mailpass123' }, logger: false });
  await client.connect();
  for (const box of await client.list()) if (!['INBOX', 'Sent', 'Trash', 'Drafts'].includes(box.path)) await client.mailboxDelete(box.path).catch(() => {});
  for (const p of ['INBOX', 'Sent', 'Trash']) { const l = await client.getMailboxLock(p); try { await client.messageDelete('1:*'); } catch {} finally { l.release(); } }
  await client.mailboxCreate('Projekte').catch(() => {});
  await client.mailboxCreate('Projekte/Größe').catch(() => {});
  let n = 0;
  for (const [box, raw, flags] of msgs) { await client.append(box, Buffer.from(raw, 'binary'), flags); n++; }
  await client.logout();
  console.log('appended', n);

  // Jeff's PC: account + contact + vault
  const store = new Store(jdir), contacts = new ContactStore(jdir);
  store.saveAccount({ name: 'Jeff Test', email: 'jeff@test.local', imapHost: '127.0.0.1', imapPort: 11993, imapSecurity: 'ssl', smtpHost: '127.0.0.1', smtpPort: 11465, username: 'jeff@test.local', password: 'mailpass123', allowSelfSigned: true });
  contacts.save({ name: 'Ann Example', emails: ['ann@friend.test'], keyFp: ak.fingerprint });
  const sync = new SyncService({ dataDir: jdir, store, pgp: jp, contacts });
  const setupCode = fs.readFileSync(process.argv[4] + '/config.php', 'utf8').match(/'setup_code'\s*=>\s*'([^']+)'/)[1];
  const st = await sync.connect({ server: serverUrl, username: 'jeff', passphrase: 'vault passphrase 1', create: true, setupCode, deviceName: 'Jeff PC' });
  console.log(JSON.stringify(st.result));
})().catch(e => { console.error(e); process.exit(1); });
