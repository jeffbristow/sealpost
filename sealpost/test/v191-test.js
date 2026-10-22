/* Sealpost 1.9.1 self-test: folders shown in their real hierarchy. */
const assert = require('assert');
const { MailService } = require('../src/main/mail');
let passed = 0;
const ok = (c, m) => { assert(c, m); passed++; console.log('  ✓', m); };
const F = (path, extra = {}) => ({ path, name: path.split('/').pop(), delimiter: '/', specialUse: null, ...extra });
const show = list => list.map(f => '  '.repeat(f.depth) + f.name).join('\n');

// a Zoho-like listing, deliberately out of order
const tree = MailService.folderTree([
  F('Trash', { specialUse: '\\Trash' }),
  F('Projects/2024'),
  F('Sent/Archive 2023'),
  F('INBOX', { name: 'Inbox', specialUse: '\\Inbox' }),
  F('Projects'),
  F('INBOX/Receipts'),
  F('Sent', { specialUse: '\\Sent' }),
  F('Projects/2024/Q1'),
  F('Clients/Acme/Invoices'),            // parents not listed at all
  F('Drafts', { specialUse: '\\Drafts' }),
  F('Projects/10 Later'),
  F('Projects/2 Soon'),
  F('Archive', { noselect: true }),      // container only
  F('Archive/Old')
]);
console.log(show(tree));
const at = n => tree.findIndex(f => f.path === n);
ok(tree[0].path === 'INBOX' && tree[1].path === 'INBOX/Receipts' && tree[1].depth === 1, 'Inbox first, its subfolder right under it');
ok(at('Drafts') < at('Sent') && at('Sent/Archive 2023') === at('Sent') + 1, 'Sent subfolder stays under Sent');
ok(at('Trash') < at('Projects'), 'special folders before your own folders');
ok(tree[at('Projects/2024/Q1')].depth === 2 && at('Projects/2024/Q1') === at('Projects/2024') + 1, 'three levels deep');
ok(at('Projects/2 Soon') < at('Projects/10 Later') && at('Projects/10 Later') < at('Projects/2024'), 'subfolders sorted naturally (2 before 10)');
ok(tree[at('Archive/Old')].depth === 1 && at('Archive/Old') === at('Archive') + 1, 'subfolder of a container-only folder stays under it');
ok(tree[at('Clients/Acme/Invoices')].depth === 0 && tree[at('Clients/Acme/Invoices')].name === 'Clients/Acme/Invoices', 'folder with unlisted parents shows its full path');
const dot = MailService.folderTree([{ path: 'INBOX', name: 'Inbox', delimiter: '.', specialUse: '\\Inbox' }, { path: 'INBOX.Work.Team', name: 'Team', delimiter: '.' }, { path: 'INBOX.Work', name: 'Work', delimiter: '.' }]);
ok(dot.map(f => f.depth).join() === '0,1,2' && dot[2].name === 'Team', 'servers using "." as separator (INBOX.Work.Team)');
console.log(`\nv191 tests: ${passed} passed`);
