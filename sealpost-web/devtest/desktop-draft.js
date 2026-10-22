const R = '/home/claude/sealpost/src/main/';
const { PgpEngine } = require(R + 'pgp'); const { readDraft } = require(R + 'reader');
const { ImapFlow } = require('/home/claude/sealpost/node_modules/imapflow');
(async () => {
  const [, , dir, pass] = process.argv;
  const c = new ImapFlow({ host: '127.0.0.1', port: 11993, secure: true, tls: { rejectUnauthorized: false }, auth: { user: 'jeff@test.local', pass: 'mailpass123' }, logger: false });
  await c.connect(); const l = await c.getMailboxLock('Drafts');
  let raw = null; for await (const m of c.fetch('1:*', { source: true })) raw = m.source;
  l.release(); await c.logout();
  if (!raw) return console.log('no draft');
  const pgp = new PgpEngine(dir); await pgp.load();
  for (const fp of pgp.privateKeys.keys()) await pgp.unlock(fp, pass);
  const d = await readDraft(raw, pgp);
  console.log(JSON.stringify({ to: d.to, subject: d.subject, html: d.html, meta: d.meta, encrypted: d.encrypted }, null, 1));
})().catch(e => console.error('ERR', e.message));
