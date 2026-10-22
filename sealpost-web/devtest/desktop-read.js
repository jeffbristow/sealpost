// Open a .eml with Sealpost desktop's reader as a given test identity
const R = '/home/claude/sealpost/src/main/';
const { PgpEngine } = require(R + 'pgp'); const { readMessage } = require(R + 'reader');
(async () => {
  const [, , dir, pass, file] = process.argv;
  const pgp = new PgpEngine(dir); await pgp.load();
  for (const fp of pgp.privateKeys.keys()) await pgp.unlock(fp, pass);
  const v = await readMessage(require('fs').readFileSync(file), pgp);
  console.log(JSON.stringify({ subject: v.subject, protectedSubject: v.pgp.protectedSubject, decrypted: v.pgp.decrypted, sigs: v.pgp.signatures.map(s => [s.valid, s.signer, s.matchesSender]), errors: v.pgp.errors, text: v.text.slice(0, 120), atts: v.attachments.map(a => a.filename) }, null, 1));
})().catch(e => console.error('ERR', e.message));
