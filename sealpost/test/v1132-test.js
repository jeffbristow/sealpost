/* Sealpost 1.13.2 self-test: account order + the folder Sealpost opens at start. Run with `npm test`. */
const os = require('os');
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const { Store } = require('../src/main/store');

const fakeSecure = tag => ({
  encrypt: s => tag + ':' + Buffer.from(s).toString('base64'),
  decrypt: b => { if (!b.startsWith(tag + ':')) throw new Error('other user'); return Buffer.from(b.slice(tag.length + 1), 'base64').toString(); }
});

let passed = 0;
const ok = (cond, msg) => { assert.ok(cond, msg); passed++; console.log('  ✓ ' + msg); };

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sealpost-v1132-'));
try {
  const store = new Store(root, fakeSecure('A'));
  const add = email => store.saveAccount({ email, imapHost: 'imap.example.org', smtpHost: 'smtp.example.org', password: 'pw' }).id;
  const [a, b, c] = ['a@example.org', 'b@example.org', 'c@example.org'].map(add);
  const emails = () => store.listAccounts().map(x => x.email[0]).join('');

  ok(emails() === 'abc', 'without an order, accounts are listed as they were added');
  store.setSettings(Store.cleanStartPrefs({ accountOrder: [c, a, b] }));
  ok(emails() === 'cab', 'accounts follow the saved order');
  store.setSettings(Store.cleanStartPrefs({ accountOrder: [b] }));
  ok(emails() === 'bac', 'accounts missing from the order keep their place after the others');
  store.setSettings(Store.cleanStartPrefs({ accountOrder: ['gone', c, c, '', a] }));
  ok(emails() === 'cab' && JSON.stringify(store.getSettings().accountOrder) === JSON.stringify(['gone', c, a]), 'duplicates and blanks are dropped; unknown ids do no harm');
  const d = add('d@example.org');
  ok(emails() === 'cabd', 'a new account goes to the end');
  store.deleteAccount(d);

  // start folder
  ok(Store.cleanStartPrefs({ startFolder: { accId: a } }).startFolder === null, 'a start folder without a path is cleared');
  ok(Store.cleanStartPrefs({ startFolder: 'x' }).startFolder === null, 'a start folder that is not an object is cleared');
  store.setSettings(Store.cleanStartPrefs({ startFolder: { accId: a, path: 'Work/Taxes', extra: 1 } }));
  ok(JSON.stringify(store.getSettings().startFolder) === JSON.stringify({ accId: a, path: 'Work/Taxes' }), 'the start folder is saved as { accId, path }');

  const moved = p => (p === 'Work' ? 'Jobs' : p.startsWith('Work/') ? 'Jobs' + p.slice(4) : p);
  store.followFolders(b, moved);
  ok(store.getSettings().startFolder.path === 'Work/Taxes', 'renaming a folder in another account leaves the start folder alone');
  store.followFolders(a, moved);
  ok(store.getSettings().startFolder.path === 'Jobs/Taxes', 'the start folder follows a renamed parent folder');
  store.followFolders(a, p => (p === 'Jobs' || p.startsWith('Jobs/') ? null : p));
  ok(store.getSettings().startFolder === null, 'deleting the start folder goes back to the first Inbox');

  ok(JSON.stringify(new Store(root, fakeSecure('A')).getSettings().accountOrder) === JSON.stringify(['gone', c, a]), 'the order is kept on disk');

  // both are synced settings, not per-device ones
  const { LOCAL_SETTINGS } = require('../src/main/sync');
  ok(!LOCAL_SETTINGS.includes('accountOrder') && !LOCAL_SETTINGS.includes('startFolder'), 'account order and start folder sync to your other devices');

  // the desktop app and Sealpost Web sort accounts the same way
  const body = f => ((fs.readFileSync(f, 'utf8').match(/orderAccounts\(accounts, order\) \{([\s\S]*?)\n\s*\}/) || [])[1] || '').replace(/\s+/g, ' ').trim();
  const desk = body(path.join(__dirname, '../src/main/store.js'));
  const web = body(path.join(__dirname, '../../sealpost-web/server/web/vault.js'));
  ok(desk && desk === web, 'orderAccounts is the same on the desktop and in Sealpost Web');
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}
console.log(`\nv1.13.2 account order + start folder tests: ${passed} passed`);
