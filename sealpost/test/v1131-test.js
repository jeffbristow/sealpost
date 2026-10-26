/* Sealpost 1.13.1 self-test: own folder icons. Run with `npm test`. */
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

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sealpost-v1131-'));
try {
  const store = new Store(root, fakeSecure('A'));
  const acc = store.saveAccount({ email: 'sam@example.org', imapHost: 'imap.example.org', smtpHost: 'smtp.example.org', password: 'pw' });
  ok(JSON.stringify(acc.folderIcons) === '{}', 'a new account has no folder icons');

  store.setAccountPrefs(acc.id, { pinnedFolders: ['Work', 'Work/Taxes'], folderIcons: { 'Work': '💼', 'Work/Taxes': '🧾', 'Bills': '💳', '': '❌', 'Junk': '', 'Long': 'x'.repeat(40) } });
  let a = store.listAccounts()[0];
  ok(JSON.stringify(a.folderIcons) === JSON.stringify({ 'Work': '💼', 'Work/Taxes': '🧾', 'Bills': '💳' }), 'icons are saved; empty paths, empty icons and long text are dropped');

  store.saveAccount({ ...store.getAccount(acc.id), folderIcons: undefined, signature: 'Sam' });
  ok(store.listAccounts()[0].folderIcons['Bills'] === '💳', 'editing the account keeps its icons');

  // the same record arriving from the vault (another device) replaces them
  store.saveAccount({ ...store.getAccount(acc.id), folderIcons: { 'INBOX': '⭐' } });
  ok(JSON.stringify(store.listAccounts()[0].folderIcons) === '{"INBOX":"⭐"}', 'icons from another device replace the local ones');

  store.setAccountPrefs(acc.id, { folderIcons: { 'Work': '💼', 'Work/Taxes': '🧾', 'Bills': '💳' } });
  const moved = p => (p === 'Work' ? 'Jobs' : p.startsWith('Work/') ? 'Jobs' + p.slice(4) : p);
  store.followFolders(acc.id, moved);
  a = store.listAccounts()[0];
  ok(JSON.stringify(a.folderIcons) === JSON.stringify({ 'Jobs': '💼', 'Jobs/Taxes': '🧾', 'Bills': '💳' }), 'icons follow a renamed folder and its subfolders');
  ok(JSON.stringify(a.pinnedFolders) === JSON.stringify(['Jobs', 'Jobs/Taxes']), 'pins follow it too');

  store.followFolders(acc.id, p => (p === 'Jobs' || p.startsWith('Jobs/') ? null : p));
  a = store.listAccounts()[0];
  ok(JSON.stringify(a.folderIcons) === '{"Bills":"💳"}' && a.pinnedFolders.length === 0, 'a deleted folder loses its icon and pin');

  // the reloaded store reads the same icons
  ok(new Store(root, fakeSecure('A')).listAccounts()[0].folderIcons['Bills'] === '💳', 'icons are kept on disk');

  // the desktop app and Sealpost Web offer the same icons
  const list = f => (fs.readFileSync(f, 'utf8').match(/const FOLDER_ICONS = \[[\s\S]*?\]\.map/) || [''])[0];
  const desk = list(path.join(__dirname, '../src/renderer/app.js'));
  const web = list(path.join(__dirname, '../../sealpost-web/server/web/app.js'));
  ok(desk && desk === web, 'the icon choices are the same on the desktop and in Sealpost Web');
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}
console.log(`\nv1.13.1 folder icon tests: ${passed} passed`);
