/* Sealpost 1.13.0 self-test: addy.io addresses — keys for the real recipient
 * (desktop src/main/addy.js + pgp.js, and Sealpost Web 1.11.0 web/addy.js + web/pgp.js). */
const os = require('os');
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const { pathToFileURL } = require('url');
const { PgpEngine } = require('../src/main/pgp');
const { ContactStore } = require('../src/main/contacts');
const addy = require('../src/main/addy');

let passed = 0;
const ok = (c, m) => { assert(c, m); passed++; console.log('  ✓', m); };

const WEB = path.join(__dirname, '..', '..', 'sealpost-web', 'server', 'web');
const ADDR = 'shop+sam=example.org@example.com';   // through the alias shop@example.com to sam@example.org

(async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sealpost-1130-'));

  // ---- 1. reading addy.io addresses ----
  const D = ['example.com', ...addy.ADDY_DOMAINS];
  ok(addy.decodeAddy(ADDR, D) === 'sam@example.org', 'alias+recipient=domain@aliasdomain -> recipient@domain');
  ok(addy.decodeAddy('Shop+Sam=Example.org@Example.COM', D) === 'sam@example.org', 'case does not matter');
  ok(addy.decodeAddy('first+hello+whatever=example.org@me.addy.io') === 'hello+whatever@example.org', "the recipient's own +tag stays (addy.io's example)");
  ok(addy.decodeAddy('a+b=c.example.net@x.anonaddy.me') === 'b@c.example.net', 'subdomains of addy.io domains count');
  ok(addy.decodeAddy(ADDR) === null, 'a custom domain is only read when it is listed');
  ok(addy.decodeAddy('sam+news@example.com', D) === null, 'a plain +tag address is not an addy.io address');
  ok(addy.decodeAddy('shop+sam@example.com', D) === null && addy.decodeAddy('+sam=example.org@example.com', D) === null, 'no "=" or no alias part: left alone');
  ok(addy.decodeAddy('shop+sam=localhost@example.com', D) === null, 'the recipient must have a real domain');
  ok(JSON.stringify(addy.cleanDomains('Example.com, @mail.example.org\nnot_a_domain, example.com')) === '["example.com","mail.example.org"]', 'domain list cleaned');

  // ---- 2. the setting ----
  const off = addy.keyAddressFn({}, []);
  ok(off(ADDR) === ADDR, 'setting off: addresses are used as typed');
  const accounts = [{ email: 'me@example.net', aliases: [{ email: 'shop@example.com' }] }];
  ok(addy.keyAddressFn({ addyRecipients: true }, accounts)(ADDR) === 'sam@example.org', 'setting on: the domain of a "Send as" address is recognised by itself');
  ok(addy.keyAddressFn({ addyRecipients: true, addyDomains: ['example.com'] }, [])(ADDR) === 'sam@example.org', 'setting on: a listed custom domain is recognised');
  ok(addy.keyAddressFn({ addyRecipients: true }, [])(ADDR) === ADDR, 'setting on, unknown domain: left alone');

  // ---- 3. encrypting to an addy.io address uses the real recipient's key ----
  const me = new PgpEngine(path.join(root, 'me')); await me.load();
  const sam = new PgpEngine(path.join(root, 'sam')); await sam.load();
  const s1 = await sam.generate({ name: 'Sam', email: 'sam@example.org', passphrase: 'sam-pass-1234' });
  await sam.unlock(s1.fingerprint, 'sam-pass-1234');
  await me.importKeys(sam.exportPublic(s1.fingerprint));
  const contacts = new ContactStore(path.join(root, 'me'));
  me.setPinnedLookup(e => contacts.pinnedFor(e));

  let settings = { addyRecipients: false, addyDomains: ['example.com'] };
  me.setAddressMap(e => addy.keyAddressFn(settings, [])(e));
  let st = (await me.recipientStatus([ADDR]))[ADDR];
  ok(!st.ok && st.keyAddress === null, 'setting off: no key for the addy.io address');
  await assert.rejects(() => me.encrypt({ data: Buffer.from('x'), recipients: [ADDR] }), e => e.code === 'MISSING_KEYS');
  ok(true, 'setting off: encrypting fails with MISSING_KEYS');

  settings = { addyRecipients: true, addyDomains: ['example.com'] };
  st = (await me.recipientStatus([ADDR]))[ADDR];
  ok(st.ok && st.fingerprint === s1.fingerprint && st.keyAddress === 'sam@example.org', 'setting on: key chip finds the real recipient\'s key');
  ok((await me.findPublicFor(ADDR)).getFingerprint().toUpperCase() === s1.fingerprint, 'findPublicFor uses the real address');
  const armored = await me.encrypt({ data: Buffer.from('through the alias'), recipients: [ADDR] });
  ok((await sam.decrypt(armored)).data.toString() === 'through the alias', 'the real recipient can decrypt it');
  ok(me.keyAddress('Bob@Example.org') === 'bob@example.org', 'ordinary addresses are unchanged');

  // ---- 4. contact-assigned keys ----
  const s2 = await sam.generate({ name: 'Sam', email: 'sam@example.org', passphrase: 'sam-pass-5678' });
  await me.importKeys(sam.exportPublic(s2.fingerprint));
  const c = contacts.save({ name: 'Sam', emails: ['sam@example.org'] });
  contacts.pinKey(c.id, s1.fingerprint);
  st = (await me.recipientStatus([ADDR]))[ADDR];
  ok(st.pinned && st.fingerprint === s1.fingerprint, 'the key assigned to the real address\'s contact is used');
  const c2 = contacts.save({ name: 'Sam via shop', emails: [ADDR] });
  contacts.pinKey(c2.id, s2.fingerprint);
  ok((await me.findPublicFor(ADDR)).getFingerprint().toUpperCase() === s2.fingerprint, 'a key assigned to the addy.io address itself comes first');

  // ---- 5. Sealpost Web: same answers ----
  const webAddy = await import(pathToFileURL(path.join(WEB, 'addy.js')).href);
  const samples = [ADDR, 'first+hello+whatever=example.org@me.addy.io', 'sam+news@example.com', 'shop+sam@example.com', 'x+y=z.example@nope.example'];
  for (const s of [{ addyRecipients: true, addyDomains: ['example.com'] }, { addyRecipients: true }, {}]) {
    const a = addy.keyAddressFn(s, accounts), b = webAddy.keyAddressFn(s, accounts);
    ok(samples.every(x => a(x) === b(x)), `web/addy.js reads addresses exactly like the desktop (${JSON.stringify(s)})`);
  }
  try {
    const { Keyring } = await import(pathToFileURL(path.join(WEB, 'pgp.js')).href);
    const kr = new Keyring();
    await kr.load([{ fingerprint: s1.fingerprint, public: sam.exportPublic(s1.fingerprint) }]);
    kr.setAddressMap(webAddy.keyAddressFn({ addyRecipients: true, addyDomains: ['example.com'] }, []));
    const ws = (await kr.recipientStatus([ADDR]))[ADDR];
    ok(ws.ok && ws.fingerprint === s1.fingerprint && ws.keyAddress === 'sam@example.org', 'Sealpost Web keyring finds the real recipient\'s key');
  } catch (e) {
    if (!/Cannot find|window|document|self is not defined/i.test(e.message)) throw e;
    console.log('  - Sealpost Web keyring not loadable in Node here (' + e.message + ')');
  }

  fs.rmSync(root, { recursive: true, force: true });
  console.log(`\nv1.13.0 addy.io tests: ${passed} passed`);
})().catch(e => { console.error('FAILED:', e); process.exit(1); });
