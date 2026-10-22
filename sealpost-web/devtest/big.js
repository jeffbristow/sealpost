const { ImapFlow } = require('/home/claude/sealpost/node_modules/imapflow');
const { deriveKeys } = require('/home/claude/sealpost/src/main/sync');
(async () => {
  const c = new ImapFlow({ host: '127.0.0.1', port: 11993, secure: true, tls: { rejectUnauthorized: false }, auth: { user: 'jeff@test.local', pass: 'mailpass123' }, logger: false });
  await c.connect();
  const att = require('crypto').randomBytes(27 * 1024 * 1024).toString('base64').replace(/.{76}/g, '$&\r\n');
  const raw = `From: Big <big@b.test>\r\nTo: jeff@test.local\r\nSubject: Big attachment\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="B"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nBig file.\r\n--B\r\nContent-Type: application/octet-stream; name="big.bin"\r\nContent-Disposition: attachment; filename="big.bin"\r\nContent-Transfer-Encoding: base64\r\n\r\n${att}\r\n--B--\r\n`;
  const r = await c.append('INBOX', raw); await c.logout();
  console.log('size MB', (raw.length / 1048576).toFixed(1), 'uid', r.uid);
  const { authKey } = await deriveKeys('vault passphrase 1', 'jeff');
  const p = (a, b, t) => fetch('http://127.0.0.1:8767/' + a, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(t ? { 'X-Sealpost-Token': t } : {}) }, body: JSON.stringify(b) });
  const l = await (await p('api.php?action=login', { username: 'jeff', authKey, deviceName: 't', kind: 'web' })).json();
  const t0 = Date.now();
  const res = await p('mail.php?action=message', { account: { host: '127.0.0.1', port: 11993, security: 'ssl', username: 'jeff@test.local', password: 'mailpass123', allowSelfSigned: true }, folder: 'INBOX', uid: r.uid }, l.token);
  const buf = Buffer.from(await res.arrayBuffer());
  console.log('status', res.status, 'bytes MB', (buf.length / 1048576).toFixed(1), 'match', buf.length === Buffer.byteLength(raw), Date.now() - t0, 'ms', buf.length < 500 ? buf.toString() : '');
})();
