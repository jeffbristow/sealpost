/* Sealpost self-test (1.11.0): every client reads every other client's vault.
 * Sealpost is one vault on many devices: the desktop app (Windows, Mac,
 * Linux — all sync.js) and Sealpost Web / the iPhone app (web/vault.js).
 * Their vault crypto is written twice, so this checks they still agree:
 * same login key + wrap key from the same passphrase, items sealed by one
 * opened by the other (both ways), the item id bound in so items can't be
 * swapped, and the same list of per-device settings. A new client must
 * pass the same checks. */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const assert = require('assert');
const { pathToFileURL } = require('url');
const desktop = require('../src/main/sync');

const WEB = process.env.SEALPOST_SERVER || path.join(__dirname, '..', '..', 'sealpost-web', 'server');
let passed = 0;
const ok = (c, m) => { assert(c, m); passed++; console.log('  ✓', m); };

(async () => {
  if (!fs.existsSync(path.join(WEB, 'web', 'vault.js'))) { console.log('clients: Sealpost Web files not found — test skipped'); return; }
  const web = await import(pathToFileURL(path.join(WEB, 'web', 'vault.js')).href);
  const kdf = { alg: 'pbkdf2-sha256', iter: 100000 };   // the real 600 000 works the same, just slower
  const user = 'Jeff@Example.test', pass = 'correct horse battery staple ✓';

  // 1. the same passphrase gives the same keys everywhere
  const d = await desktop.deriveKeys(pass, user, kdf);
  const w = await web.deriveKeys(pass, user, kdf);
  ok(d.authKey === w.authKey, 'same login key on desktop and web');
  ok(d.authKey === (await desktop.deriveKeys(pass, ' jeff@example.test ', kdf)).authKey, 'username case and spaces don\'t matter');

  // 2. the vault key wrapped on the desktop opens on the web
  const vaultKey = crypto.randomBytes(32);
  const wrapped = desktop.seal(d.wrapKey, vaultKey, 'sealpost-vault-key');
  const unwrapped = await web.unseal(w.wrapKey, wrapped, 'sealpost-vault-key');
  ok(Buffer.from(unwrapped).equals(vaultKey), 'vault key wrapped on desktop opens on web');

  // 3. items both ways (the envelope both write: { v, id, type, updated, device, data })
  const webKey = await crypto.webcrypto.subtle.importKey('raw', vaultKey, 'AES-GCM', false, ['encrypt', 'decrypt']);
  const item = (id, type, data, device) => ({ v: 1, id, type, updated: Date.now(), device, data });
  const contact = item('contact:c1', 'contact', { name: 'Ann Example', emails: ['ann@friend.test'], keyFp: 'ABCD1234', encrypt: 'always' }, 'Jeff\'s Mac');
  const fromDesktop = desktop.seal(vaultKey, Buffer.from(JSON.stringify(contact)), contact.id);
  const openedOnWeb = JSON.parse(new TextDecoder().decode(await web.unseal(webKey, fromDesktop, contact.id)));
  ok(JSON.stringify(openedOnWeb) === JSON.stringify(contact), 'contact saved on desktop opens on web');

  const settings = item('settings:main', 'settings', { defaultSign: true, defaultEncrypt: true, pageSize: 75, composeFormat: 'rich' }, 'Sealpost Web');
  const fromWeb = await web.seal(webKey, new TextEncoder().encode(JSON.stringify(settings)), settings.id);
  const openedOnDesktop = JSON.parse(desktop.unseal(vaultKey, fromWeb, settings.id).toString('utf8'));
  ok(JSON.stringify(openedOnDesktop) === JSON.stringify(settings), 'settings saved on web open on desktop');

  // 4. an item can't be passed off as another one (the id is sealed in)
  assert.throws(() => desktop.unseal(vaultKey, fromWeb, 'settings:other'));
  await assert.rejects(web.unseal(webKey, fromDesktop, 'contact:c2'));
  ok(true, 'an item sealed for one id is refused under another id (desktop and web)');

  // 5. per-device settings: the same list everywhere (else one client syncs what another keeps local)
  const webLocal = JSON.parse(/const LOCAL_SETTINGS = (\[[^\]]*\])/.exec(fs.readFileSync(path.join(WEB, 'web', 'settings.js'), 'utf8'))[1].replace(/'/g, '"'));
  ok(JSON.stringify(webLocal) === JSON.stringify(desktop.LOCAL_SETTINGS), 'same per-device settings on desktop and web: ' + webLocal.join(', '));

  console.log(`\nclients tests: ${passed} passed`);
})().catch(e => { console.error('FAILED:', e); process.exit(1); });
