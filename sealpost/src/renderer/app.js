/* =====================================================================
 * Sealpost — app.js  (user interface logic)
 * ---------------------------------------------------------------------
 * Sections:
 *   1.  Helpers (DOM, escaping, dates, toasts)
 *   2.  API wrapper with automatic passphrase prompt + retry
 *   3.  Modals (generic dialog, passphrase)
 *   4.  Navigation between views
 *   5.  Accounts + folder tree (sidebar)
 *   6.  Message list (paging, search, refresh, new-mail notifications)
 *   7.  Reader (body, PGP status banner, attachments, actions)
 *   8.  Composer (reply/forward, recipient key status, send)
 *   9.  Key manager
 *   10. PGP tools
 *   11. Settings + account editor (11b app lock, 11c backup, 11d sync)
 *   12. Keyboard shortcuts + startup
 * ===================================================================== */

'use strict';

/* =================================================================
 * 1. HELPERS
 * ================================================================= */
const $ = sel => document.querySelector(sel);
const $$ = sel => [...document.querySelectorAll(sel)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const show = (el, on = true) => el.classList.toggle('hidden', !on);

/* ---------- 1.8.0: words that differ outside Windows ----------
 * The screens were written for Windows ("your Windows login",
 * %APPDATA%…). On Linux the same features use the login keyring and
 * ~/.config, so a few phrases are swapped when the page loads and in
 * dialogs. On Windows nothing changes. */
const PLATFORM = (window.api && window.api.platform) || 'win32';
// 1.11.0: shortcuts written as Ctrl+… also work with ⌘ on a Mac
const MOD = e => e.ctrlKey || (PLATFORM === 'darwin' && e.metaKey);
const OS_WORDS = PLATFORM === 'win32' ? [] : [
  [/%APPDATA%\\Sealpost/g, PLATFORM === 'darwin' ? '~/Library/Application Support/Sealpost' : '~/.config/Sealpost'],
  [/default Windows program/g, 'default program'],
  [/a Windows notification/g, 'a desktop notification'],
  [/\(protected by your Windows login\)/g, '(protected by your login keyring)'],
  [/encrypted with your Windows login/g, 'encrypted with your login keyring'],
  [/Windows secure storage/g, 'secure storage'],
  [/sign in to your Windows account/g, 'sign in to your user account'],
  [/ \(or Windows Hello\)/g, ''],
  [/PIN \/ Windows Hello to reopen/g, 'PIN to reopen'],
  [/,? and when Windows locks/g, PLATFORM === 'darwin' ? ' and when the screen locks' : ''],
  [/only on start \/ Windows lock/g, PLATFORM === 'darwin' ? 'only on start / screen lock' : 'only on start'],
  [/Windows Hello/g, 'fingerprint unlock']
];
const osText = s => OS_WORDS.reduce((t, [re, to]) => t.replace(re, to), String(s ?? ''));
function osFixPage(root = document.body) {
  if (!OS_WORDS.length) return;
  const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  for (let n; (n = w.nextNode());) { const t = osText(n.nodeValue); if (t !== n.nodeValue) n.nodeValue = t; }
  root.querySelectorAll('[title]').forEach(el => { el.title = osText(el.title); });
}
osFixPage();
document.documentElement.dataset.platform = PLATFORM;
// 1.8.0: Linux without a login keyring — say so under Settings
if (PLATFORM === 'linux') window.api.pgpCanRemember().then(r => {
  if (r.ok && r.data) return;
  const p = [...document.querySelectorAll('#view-settings p, p')].find(x => /Data folder:/.test(x.textContent));
  if (p) p.insertAdjacentHTML('afterend', '<p class="muted small" style="color:var(--amber)">No login keyring (GNOME Keyring or KDE Wallet) was found, so mail passwords are only scrambled — in a folder only your user can open. Install or unlock a keyring and Sealpost encrypts them automatically on the next start.</p>');
}).catch(() => {});

function fmtDate(iso, long = false) {
  if (!iso) return '';
  const d = new Date(iso), now = new Date();
  if (long) return d.toLocaleString(undefined, { dateStyle: 'full', timeStyle: 'short' });
  if (d.toDateString() === now.toDateString()) return d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
  if (d.getFullYear() === now.getFullYear()) return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  return d.toLocaleDateString();
}

function fmtSize(n) {
  if (n == null) return '';
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(0) + ' KB';
  return (n / 1048576).toFixed(1) + ' MB';
}

const addr = a => a ? (a.name ? `${a.name} <${a.address}>` : a.address) : '';
const addrShort = a => a ? (a.name || a.address) : '';

function toast(msg, kind = '') {
  const t = document.createElement('div');
  t.className = 'toast ' + kind;
  t.textContent = msg;
  $('#toasts').appendChild(t);
  setTimeout(() => t.remove(), kind === 'err' ? 9000 : 4500);
}

/* =================================================================
 * 2. API WRAPPER — prompts for a passphrase when a key is locked,
 *    unlocks it, then retries the original call automatically.
 * ================================================================= */
async function call(name, ...args) {
  for (let attempt = 0; attempt < 4; attempt++) {
    const r = await window.api[name](...args);
    if (r.ok) return r.data;
    if (r.code === 'NEED_PASSPHRASE') {
      const unlocked = await promptPassphrase(r.fingerprint, r.userId);
      if (!unlocked) throw Object.assign(new Error('Cancelled — key stays locked'), { code: 'CANCELLED' });
      continue;
    }
    if (r.code === 'LOCKED') { showLockScreen(); throw Object.assign(new Error('Sealpost is locked'), { code: 'LOCKED' }); }
    throw Object.assign(new Error(r.error), r);
  }
  throw new Error('Too many attempts');
}

/* =================================================================
 * 3. MODALS
 * ================================================================= */
function openModal(id) { show($(id), true); }
function closeModal(id) { show($(id), false); }
$$('[data-close]').forEach(b => b.addEventListener('click', () => {
  const m = b.closest('.modal');
  if (m._cancel) m._cancel(); else m.classList.add('hidden');
}));

// Generic dialog. opts: { title, html, okText, cancelText, hideCancel, onOk(): value|false }
// extraText adds a third button that resolves to 'extra' (1.1.0)
function dialog({ title, html, okText = 'OK', cancelText = 'Cancel', hideCancel = false, onOk, danger = false, extraText = null }) {
  return new Promise(resolve => {
    $('#dlgTitle').textContent = title;
    $('#dlgBody').innerHTML = osText(html);   // 1.8.0
    const ok = $('#dlgOk'), cancel = $('#dlgCancel'), extra = $('#dlgExtra');
    ok.textContent = okText;
    ok.classList.toggle('danger', danger);
    cancel.textContent = cancelText;
    show(cancel, !hideCancel);
    extra.textContent = extraText || '';
    show(extra, !!extraText);
    openModal('#dlgModal');
    const modal = $('#dlgModal');
    const done = v => { closeModal('#dlgModal'); ok.onclick = cancel.onclick = extra.onclick = null; modal._cancel = null; resolve(v); };
    modal._cancel = () => done(null);
    extra.onclick = () => done('extra');
    ok.onclick = async () => {
      const v = onOk ? await onOk() : true;
      if (v !== false) done(v);
    };
    cancel.onclick = () => done(null);
    const first = $('#dlgBody').querySelector('input,textarea');
    if (first) setTimeout(() => first.focus(), 30);
  });
}

const confirmBox = (title, text, okText = 'OK', danger = false) =>
  dialog({ title, html: `<p>${esc(text)}</p>`, okText, danger });

// Passphrase prompt; resolves true when the key was unlocked
function promptPassphrase(fp, userId) {
  return new Promise(resolve => {
    $('#passWho').textContent = (userId || 'Private key') + '  ·  ' + (fp ? fp.replace(/(.{4})/g, '$1 ').trim().slice(-24) : '');
    $('#passInput').value = '';
    $('#passErr').textContent = '';
    $('#passRemember').checked = false;
    // 1.0.2: only offer "remember" when Windows secure storage is available
    window.api.pgpCanRemember().then(r => {
      const can = !!(r.ok && r.data);
      show($('#passRememberRow'), can);
      // 1.8.0: on Linux, say why "Remember" is missing
      if (!can && PLATFORM === 'linux') $('#passRememberNote').textContent = 'To remember passphrases on this computer, Sealpost needs a login keyring (GNOME Keyring or KDE Wallet). Or use "Remember passphrase on all my devices" under Keys.';
      else $('#passRememberNote').textContent = osText('Encrypted messages will open without asking. Anyone who can sign in to your Windows account could read them too.');
      show($('#passRememberNote'), can || PLATFORM === 'linux');
    });
    openModal('#passModal');
    setTimeout(() => $('#passInput').focus(), 30);
    const finish = v => { closeModal('#passModal'); $('#passOk').onclick = $('#passCancel').onclick = $('#passInput').onkeydown = null; resolve(v); };
    const tryUnlock = async () => {
      $('#passOk').disabled = true;
      const remember = $('#passRemember').checked;
      const r = await window.api.pgpUnlock(fp, $('#passInput').value, remember);
      $('#passOk').disabled = false;
      if (r.ok) { if (remember) toast('Passphrase remembered — this key will unlock automatically.'); finish(true); }
      else { $('#passErr').textContent = r.error; $('#passInput').select(); }
    };
    $('#passOk').onclick = tryUnlock;
    $('#passCancel').onclick = () => finish(false);
    $('#passInput').onkeydown = e => { if (e.key === 'Enter') tryUnlock(); if (e.key === 'Escape') finish(false); };
  });
}

/* =================================================================
 * 4. NAVIGATION
 * ================================================================= */
function switchView(name) {
  $$('.nav-btn[data-view]').forEach(b => b.classList.toggle('active', b.dataset.view === name));
  $$('.view').forEach(v => v.classList.toggle('active', v.id === 'view-' + name));
  if (name === 'keys') loadKeys();
  if (name === 'contacts') loadContacts();
  if (name === 'tools') loadToolSigners();
  if (name === 'settings') loadSettingsView();
}
$$('.nav-btn[data-view]').forEach(b => b.addEventListener('click', () => switchView(b.dataset.view)));
$('#btnLockAll').addEventListener('click', async () => { await call('pgpLockAll'); toast('All private keys locked. Keys with a saved passphrase still unlock automatically — use Keys → Forget saved passphrase to stop that.'); });

/* =================================================================
 * 5. ACCOUNTS + FOLDER TREE
 * ================================================================= */
const state = {
  settings: {},
  accounts: [],
  folders: {},          // accId -> [folders]
  cur: { accId: null, folder: 'INBOX', page: 0, search: '' },
  messages: [],
  hasMore: false,
  selectedUid: null,
  view: null,           // currently open message view
  knownUids: {},        // for new-mail notifications
  keys: [],
  selectedKey: null,
  selected: new Set(),  // 1.7.0: messages ticked for a bulk action
  selectMode: false,
  anchor: null,         // last clicked row (Shift-click ranges)
  expanded: new Set()   // 1.10.0: conversations opened up in the list
};

/* ---------- 1.10.0: All Inboxes + where a message lives ----------
 * In "All Inboxes" (state.cur.accId === UNIFIED) every message in the
 * list carries its own account; its list key is "accountId:uid" so uids
 * from different accounts never clash. loc() turns a list key back into
 * { accId, folder, uid } for the mail calls; perBox() runs a call once
 * per account/folder for a mixed selection. */
const UNIFIED = '__all__';
const isUnified = () => state.cur.accId === UNIFIED;
function loc(key) {
  const m = state.messages.find(x => x.uid === key);
  return m ? { accId: m.accId || state.cur.accId, folder: m.folder || state.cur.folder, uid: m.realUid ?? m.uid }
    : { accId: state.cur.accId, folder: state.cur.folder, uid: key };
}
async function perBox(keys, fn) {
  const groups = new Map();
  for (const k of [].concat(keys)) {
    const l = loc(k), g = l.accId + '\u0001' + l.folder;
    if (!groups.has(g)) groups.set(g, { accId: l.accId, folder: l.folder, uids: [] });
    groups.get(g).uids.push(l.uid);
  }
  const out = [];
  for (const g of groups.values()) out.push(await fn(g.accId, g.folder, g.uids));
  return out;
}
const accountsOf = keys => new Set([].concat(keys).map(k => loc(k).accId));

async function loadAccounts() {
  state.accounts = await call('accountsList');
  renderTree();
  if (!state.accounts.length) {
    $('#messageList').innerHTML = `<div class="list-empty">No email account yet.<br><br><button class="btn primary" id="firstAcct">Add your first account</button></div>`;
    $('#firstAcct').onclick = () => openAccountEditor();
    return;
  }
  if (state.cur.accId === UNIFIED && state.accounts.length < 2) state.cur.accId = null;   // 1.10.0
  // 1.9.2: show what's saved on this PC at once (offline mail), then the
  // server's folders as each account answers — a slow or unreachable
  // account no longer holds up the others or the message list.
  await Promise.all(state.accounts.map(async a => {
    if (state.folders[a.id] && state.folders[a.id].length) return;
    try { const f = await call('mailFoldersCached', a.id); if (f) state.folders[a.id] = f; } catch { /* nothing saved */ }
  }));
  if (!state.cur.accId || (state.cur.accId !== UNIFIED && !state.accounts.find(a => a.id === state.cur.accId))) Object.assign(state.cur, startTarget());   // 1.13.2
  renderTree();
  selectFolder(state.cur.accId, state.cur.folder);
  await Promise.all(state.accounts.map(a => loadFolders(a.id)));
}

async function loadFolders(accId) {
  if (accId === UNIFIED) return Promise.all(state.accounts.map(a => loadFolders(a.id)));   // 1.10.0
  try {
    state.folders[accId] = await call('mailFolders', accId);
  } catch (e) {
    if (!(state.folders[accId] || []).length) state.folders[accId] = [];   // 1.9.2: keep the saved list if there is one
    toast(`${state.accounts.find(a => a.id === accId)?.email}: ${e.message}`, 'err');
  }
  renderTree();
}

/* ---------- 1.13.2: your account order + the folder Sealpost opens at start ----------
 * Both are synced settings: accountOrder = [account ids] (store.js puts
 * the accounts in that order), startFolder = { accId, path } — accId
 * UNIFIED for All Inboxes — or null for the first account's Inbox. */
const startPref = () => (state.settings && state.settings.startFolder) || null;
const isStart = (accId, path) => { const sf = startPref(); return !!sf && sf.accId === accId && sf.path === path; };
function startTarget() {
  const sf = startPref();
  if (sf && sf.accId === UNIFIED && state.accounts.length > 1) return { accId: UNIFIED, folder: 'INBOX' };
  const a = sf && state.accounts.find(x => x.id === sf.accId);
  const known = a && state.folders[a.id];
  if (a && (!known || !known.length || known.some(f => f.path === sf.path && !f.noselect))) return { accId: a.id, folder: sf.path };
  return { accId: state.accounts[0].id, folder: 'INBOX' };
}
async function setStartFolder(accId, path, name) {
  try {
    state.settings = await call('settingsSet', { startFolder: accId ? { accId, path } : null });
    toast(accId ? `Sealpost will open ${name} when it starts.` : 'Sealpost will open the first account\'s Inbox when it starts.');
  } catch (e) { toast(e.message, 'err'); }
}
async function moveAccount(accId, delta) {
  const ids = state.accounts.map(a => a.id), i = ids.indexOf(accId), j = i + delta;
  if (i < 0 || j < 0 || j >= ids.length) return;
  [ids[i], ids[j]] = [ids[j], ids[i]];
  try {
    state.settings = await call('settingsSet', { accountOrder: ids });
    await refreshAccountsQuiet();
    if ($('#view-settings').classList.contains('active')) { renderAccountList(); renderStartChoice(); }
  } catch (e) { toast(e.message, 'err'); }
}
const startMenuItem = (accId, path, name) => (isStart(accId, path)
  ? { label: '🏠 Stop opening here at start', run: () => setStartFolder(null) }
  : { label: '🏠 Open here when Sealpost starts', run: () => setStartFolder(accId, path, name) });

const folderIcon = f => ({ '\\Inbox': '📥', '\\Sent': '📤', '\\Drafts': '📝', '\\Trash': '🗑', '\\Junk': '⚠', '\\Archive': '🗄', '\\Flagged': '⚑', '\\All': '📚' }[f.specialUse] || '📁');

function renderTree() {
  const tree = $('#accountTree');
  tree.innerHTML = '';
  const multi = state.accounts.length > 1;

  // 1.10.0: favourites — All Inboxes (2+ accounts) and pinned folders
  const pins = [];
  for (const a of state.accounts) for (const p of a.pinnedFolders || []) {
    const f = (state.folders[a.id] || []).find(x => x.path === p);
    pins.push({ a, f: f || { path: p, name: p.split(/[/.]/).pop(), specialUse: null, unseen: 0 } });
  }
  if (multi || pins.length) {
    const lbl = document.createElement('div');
    lbl.className = 'acct-label';
    lbl.textContent = 'Favorites';
    tree.appendChild(lbl);
    if (multi) {
      const unread = state.accounts.reduce((n, a) => n + (((state.folders[a.id] || []).find(f => f.path.toUpperCase() === 'INBOX') || {}).unseen || 0), 0);
      const el = document.createElement('div');
      el.className = 'folder fav' + (state.cur.accId === UNIFIED ? ' active' : '');
      el.innerHTML = `<span>📬</span><span class="name">All Inboxes</span>${unread ? `<span class="count">${unread}</span>` : ''}`;
      el.title = 'The Inbox of every account in one list';
      el.onclick = () => { switchView('mail'); selectFolder(UNIFIED, 'INBOX'); };
      el.oncontextmenu = e => { e.preventDefault(); showMenu(e, [{ label: '✓ Mark all inboxes as read', run: () => markFolderRead(UNIFIED, 'INBOX') }, startMenuItem(UNIFIED, 'INBOX', 'All Inboxes')]); };
      tree.appendChild(el);
    }
    for (const { a, f } of pins) tree.appendChild(folderRow(a, f, { pinned: true, multi }));
  }

  state.accounts.forEach((a, i) => {
    const lbl = document.createElement('div');
    lbl.className = 'acct-label';
    lbl.innerHTML = `<span class="acct-name">${esc(a.name ? `${a.name} · ${a.email}` : a.email)}</span><button class="acct-add" title="New folder">＋</button>`;
    lbl.title = a.email;
    lbl.querySelector('.acct-add').onclick = e => { e.stopPropagation(); newFolderDialog(a.id, null); };   // 1.10.0
    lbl.oncontextmenu = e => { e.preventDefault(); showMenu(e, [
      { label: '＋ New folder…', run: () => newFolderDialog(a.id, null) },
      { label: (a.conversationView ? '☑' : '☐') + ' Conversation view', run: () => setConversation(a.id, !a.conversationView) },
      ...(multi ? ['-',   // 1.13.2
        ...(i > 0 ? [{ label: '▲ Move account up', run: () => moveAccount(a.id, -1) }] : []),
        ...(i < state.accounts.length - 1 ? [{ label: '▼ Move account down', run: () => moveAccount(a.id, 1) }] : [])] : [])
    ]); };
    tree.appendChild(lbl);
    for (const f of state.folders[a.id] || []) tree.appendChild(folderRow(a, f, {}));
  });
}

/** One folder line in the sidebar (also used for pinned folders). */
function folderRow(a, f, { pinned = false, multi = false } = {}) {
  const el = document.createElement('div');
  el.className = 'folder' + (pinned ? ' fav' : '') + (a.id === state.cur.accId && f.path === state.cur.folder ? ' active' : '');
  if (!pinned) el.style.paddingLeft = (10 + (f.depth || 0) * 14) + 'px';
  const label = pinned && multi ? `${f.name} <span class="muted small">· ${esc(a.email)}</span>` : esc(f.name);
  const icon = (a.folderIcons || {})[f.path] || defaultIcon(f, pinned);   // 1.13.1
  el.innerHTML = `<span>${esc(icon)}</span><span class="name">${label}</span>${f.unseen ? `<span class="count">${f.unseen}</span>` : ''}`;
  if (pinned) el.title = `${a.email} › ${f.path}`;
  el.oncontextmenu = e => { e.preventDefault(); showMenu(e, folderMenuItems(a, f, pinned)); };
  if (f.noselect) { el.classList.add('noselect'); el.title = 'This folder only holds other folders'; return el; }   // 1.9.1
  el.onclick = () => { switchView('mail'); selectFolder(a.id, f.path); };
  // 1.10.0: drop messages here to move them
  el.ondragover = e => { if (dragInfo && dragInfo.accIds.size === 1 && dragInfo.accIds.has(a.id) && !(dragInfo.folder === f.path)) { e.preventDefault(); el.classList.add('drop'); } };
  el.ondragleave = () => el.classList.remove('drop');
  el.ondrop = e => { e.preventDefault(); el.classList.remove('drop'); if (dragInfo) moveMessages(dragInfo.keys, a.id, f.path); };
  return el;
}

/* =================================================================
 * 5b. FOLDER MANAGEMENT + PINS (1.10.0)
 *     Right-click a folder: pin, new subfolder, rename, move, delete.
 *     Inbox and the special folders (Sent, Drafts, Trash…) can't be
 *     renamed, moved or deleted. Pins sync to your other devices.
 * ================================================================= */
const isSpecial = f => !!f.specialUse || f.path.toUpperCase() === 'INBOX';
const delimOf = accId => ((state.folders[accId] || []).find(f => f.delimiter) || {}).delimiter || '/';

function folderMenuItems(a, f, inFavorites = false) {
  const pinned = (a.pinnedFolders || []).includes(f.path);
  const items = [];
  if (!f.noselect) items.push({ label: '✓ Mark all as read', run: () => markFolderRead(a.id, f.path) }, '-');
  items.push({ label: pinned ? '📌 Unpin from top' : '📌 Pin to top', run: () => togglePin(a.id, f.path) });
  if (!f.noselect) items.push(startMenuItem(a.id, f.path, `"${f.name}"`));   // 1.13.2
  items.push({ label: '🎨 Choose icon…', run: () => folderIconDialog(a, f, inFavorites) });   // 1.13.1
  items.push({ label: '＋ New subfolder…', run: () => newFolderDialog(a.id, f.path) });
  if (!isSpecial(f)) {
    items.push({ label: '✎ Rename…', run: () => renameFolderDialog(a.id, f) });
    items.push({ label: '↳ Move folder to…', run: () => moveFolderDialog(a.id, f) });
    items.push('-', { label: '🗑 Delete folder…', danger: true, run: () => deleteFolderDialog(a.id, f) });
  }
  return items;
}

async function refreshAccountsQuiet() {
  try { state.accounts = await call('accountsList'); } catch { /* keep */ }
  renderTree();
}

async function togglePin(accId, path) {
  const a = state.accounts.find(x => x.id === accId);
  if (!a) return;
  const list = a.pinnedFolders || [];
  const next = list.includes(path) ? list.filter(p => p !== path) : [...list, path];
  try { await call('accountsSetPrefs', accId, { pinnedFolders: next }); a.pinnedFolders = next; renderTree(); }
  catch (e) { toast(e.message, 'err'); }
}

/* 1.13.1: own folder icons. Right-click a folder -> Choose icon…; synced like pins. */
const FOLDER_ICONS = [
  ['Mail & folders', '📁 📂 🗂️ 📥 📤 📬 📮 ✉️ 📨 📝 📌 🔖 🏷️ ⭐ ❤️ 🔥 ⚡ ✅'],
  ['Work & money', '💼 🏢 📊 📈 💰 💳 🧾 🏦 📄 📑 🗓️ ⏰ 🧮 🖨️'],
  ['Home & people', '🏠 👪 👤 👥 🐶 🐱 🎁 🛒 🍽️ ☕ 🏥 💊 🎓 📚'],
  ['Travel & fun', '✈️ 🚗 🏖️ 🗺️ 🎵 🎮 🎬 📷 ⚽ ⚾ 🏀 🎨 🧩 🌱'],
  ['Tech & security', '💻 📱 🔒 🔑 🛡️ ⚙️ 🔔 🌐 🐞 🤖 📦 🧪'],
  ['Colors', '🔴 🟠 🟡 🟢 🔵 🟣 🟤 ⚫ ⚪ 🟥 🟧 🟨 🟩 🟦 🟪']
].map(([group, list]) => [group, list.split(' ')]);
const defaultIcon = (f, pinned) => (pinned ? '📌' : folderIcon(f));

async function folderIconDialog(a, f, pinned) {
  const key = f.path, cur = (a.folderIcons || {})[key] || '';
  const p = dialog({
    title: 'Folder icon', okText: 'Use this icon', extraText: cur ? 'Use default icon' : null,
    html: `<p class="small">Pick an icon for <b>${esc(f.name)}</b>. It shows wherever the folder is listed, also under Favorites, and syncs to your other devices.</p>
      <div class="icon-picker">${FOLDER_ICONS.map(([g, list]) => `<div class="icon-group">${esc(g)}</div><div class="icon-grid">${list.map(ic =>
        `<button type="button" class="icon-pick${ic === cur ? ' sel' : ''}" data-icon="${ic}">${ic}</button>`).join('')}</div>`).join('')}</div>
      <p id="icErr" class="error"></p>`,
    onOk: () => {
      const s = document.querySelector('#dlgBody .icon-pick.sel');
      if (s) return s.dataset.icon;
      document.querySelector('#icErr').textContent = 'Click an icon first.';
      return false;
    }
  });
  document.querySelectorAll('#dlgBody .icon-pick').forEach(b => {
    b.onclick = () => { document.querySelectorAll('#dlgBody .icon-pick.sel').forEach(x => x.classList.remove('sel')); b.classList.add('sel'); };
    b.ondblclick = () => { b.onclick(); document.querySelector('#dlgOk').click(); };
  });
  const r = await p;
  if (r === 'extra') return setFolderIcon(a.id, key, '');
  if (r && r !== cur) return setFolderIcon(a.id, key, r);
}

async function setFolderIcon(accId, path, icon) {
  const a = state.accounts.find(x => x.id === accId);
  if (!a) return;
  const next = { ...(a.folderIcons || {}) };
  if (icon) next[path] = icon; else delete next[path];
  try { await call('accountsSetPrefs', accId, { folderIcons: next }); a.folderIcons = next; renderTree(); }
  catch (e) { toast(e.message, 'err'); }
}

async function setConversation(accId, on) {
  const a = state.accounts.find(x => x.id === accId);
  try { await call('accountsSetPrefs', accId, { conversationView: on }); if (a) a.conversationView = on; }
  catch (e) { return toast(e.message, 'err'); }
  state.expanded.clear();
  renderTree(); renderList(); updateConvButton();
  toast(`Conversation view ${on ? 'on' : 'off'} for ${a ? a.email : 'this account'}.`);
}

/** Ask for a folder name; checks it can be used on this server. */
function askFolderName(title, intro, value, accId) {
  const d = delimOf(accId);
  return dialog({
    title, okText: 'Save',
    html: `<p class="small">${intro}</p><input type="text" id="fnName" value="${esc(value || '')}" spellcheck="false"><p id="fnErr" class="error"></p>`,
    onOk: () => {
      const v = $('#fnName').value.trim();
      if (!v) { $('#fnErr').textContent = 'Enter a name.'; return false; }
      if (v.includes(d)) { $('#fnErr').textContent = `A folder name can't contain "${d}" on this server.`; return false; }
      return v;
    }
  });
}

async function newFolderDialog(accId, parent) {
  const pf = parent && (state.folders[accId] || []).find(f => f.path === parent);
  const name = await askFolderName('New folder', parent ? `New folder inside <b>${esc(pf ? pf.name : parent)}</b>:` : 'Name of the new folder:', '', accId);
  if (!name) return;
  const path = parent ? parent + delimOf(accId) + name : name;
  try { await call('mailCreateFolder', accId, path); await loadFolders(accId); toast(`Folder "${name}" created.`); }
  catch (e) { toast(e.message, 'err'); }
}

/** A folder (or one inside it) changed path: keep the open folder in view. */
function followPath(accId, from, to) {
  const d = delimOf(accId);
  if (state.cur.accId === accId && (state.cur.folder === from || state.cur.folder.startsWith(from + d))) {
    if (to == null) selectFolder(accId, 'INBOX'); else selectFolder(accId, to + state.cur.folder.slice(from.length));
  }
}

async function renameFolderDialog(accId, f) {
  const d = delimOf(accId);
  const leaf = f.path.split(d).pop();
  const name = await askFolderName('Rename folder', `New name for <b>${esc(f.name)}</b>:`, leaf, accId);
  if (!name || name === leaf) return;
  const i = f.path.lastIndexOf(d);
  const to = (i > 0 ? f.path.slice(0, i + 1) : '') + name;
  try {
    await call('mailRenameFolder', accId, f.path, to);
    followPath(accId, f.path, to);
    await refreshAccountsQuiet(); await loadFolders(accId);
    toast(`Renamed to "${name}".`);
  } catch (e) { toast(e.message, 'err'); }
}

async function moveFolderDialog(accId, f) {
  const d = delimOf(accId);
  const leaf = f.path.split(d).pop();
  const options = (state.folders[accId] || []).filter(x => x.path !== f.path && !x.path.startsWith(f.path + d));
  const r = await dialog({
    title: 'Move folder', okText: 'Move',
    html: `<p class="small">Move <b>${esc(f.name)}</b> (and its subfolders) into:</p>
      <select id="mvParent"><option value="">— Top level —</option>${options.map(x => `<option value="${esc(x.path)}">${' '.repeat((x.depth || 0) * 3)}${esc(x.name)}</option>`).join('')}</select>`,
    onOk: () => ({ parent: $('#mvParent').value })
  });
  if (!r) return;
  const to = (r.parent ? r.parent + d : '') + leaf;
  if (to === f.path) return;
  try {
    await call('mailRenameFolder', accId, f.path, to);
    followPath(accId, f.path, to);
    await refreshAccountsQuiet(); await loadFolders(accId);
    toast(`Moved "${leaf}".`);
  } catch (e) { toast(e.message, 'err'); }
}

async function deleteFolderDialog(accId, f) {
  const d = delimOf(accId);
  const subs = (state.folders[accId] || []).filter(x => x.path.startsWith(f.path + d));
  const n = (f.total || 0) + subs.reduce((t, x) => t + (x.total || 0), 0);
  const ok = await confirmBox('Delete folder',
    `Delete "${f.name}"${subs.length ? ` and its ${subs.length} subfolder${subs.length === 1 ? '' : 's'}` : ''}${n ? ` — including ${n} message${n === 1 ? '' : 's'}` : ''}? This deletes ${n ? 'them' : 'it'} on the mail server and can't be undone.`, 'Delete', true);
  if (!ok) return;
  try {
    // subfolders first: some servers refuse to delete a folder that still has children
    for (const x of subs.sort((p, q) => q.path.length - p.path.length)) await call('mailDeleteFolder', accId, x.path);
    await call('mailDeleteFolder', accId, f.path);
    followPath(accId, f.path, null);
    await refreshAccountsQuiet(); await loadFolders(accId);
    toast(`Deleted "${f.name}".`);
  } catch (e) { toast(e.message, 'err'); await loadFolders(accId); }
}

function selectFolder(accId, folder) {
  Object.assign(state.cur, { accId, folder, page: 0, search: '' });
  state.selected.clear(); state.selectMode = false; // 1.7.0
  state.messages = [];                              // 1.9.2: so the saved copy of the new folder can show at once
  $('#searchBox').value = '';
  const f = (state.folders[accId] || []).find(x => x.path === folder);
  $('#folderTitle').textContent = accId === UNIFIED ? 'All Inboxes' : f ? f.name : folder.toUpperCase() === 'INBOX' ? 'Inbox' : folder;
  state.expanded.clear();   // 1.10.0
  updateConvButton();
  renderPushStatus(); // 1.2.0
  show($('#offlineBar'), state.offlineAcc.has(accId)); // 1.3.0
  renderTree();
  closeReader();
  loadMessages();
}

/* =================================================================
 * 6. MESSAGE LIST
 * ================================================================= */
/** All Inboxes: give each message a list key that is unique across accounts. */
function keyed(res) {
  if (!res) return res;
  for (const m of res.messages) { m.realUid = m.uid; m.uid = m.accId + ':' + m.uid; }
  return res;
}

async function loadMessages({ append = false, silent = false } = {}) {
  const { accId, folder, page, search } = state.cur;
  if (!accId) return;
  // 1.9.2: first page of a folder saved on this PC shows instantly; the server's list replaces it a moment later
  if (!append && !silent && !search && page === 0) {
    try {
      const saved = accId === UNIFIED ? keyed(await call('mailListUnifiedCached', { page: 0 })) : await call('mailListCached', accId, folder, { page: 0 });
      if (saved && accId === state.cur.accId && folder === state.cur.folder && !state.messages.length) {
        state.messages = saved.messages; state.hasMore = saved.hasMore;
        $('#folderCount').textContent = saved.total ? `· ${saved.total}` : '';
        renderList();
        silent = true;
      }
    } catch { /* nothing saved: normal loading */ }
  }
  if (!append && !silent) $('#messageList').innerHTML = '<div class="list-empty">Loading…</div>';
  try {
    const res = accId === UNIFIED ? keyed(await call('mailListUnified', { page, search })) : await call('mailList', accId, folder, { page, search });
    if (accId !== state.cur.accId || folder !== state.cur.folder) return; // user moved on
    if (accId === UNIFIED && res.errors && res.errors.length && !silent) toast(res.errors.join(' · '), 'err');
    state.messages = append ? state.messages.concat(res.messages) : res.messages;
    for (const uid of [...state.selected]) if (!state.messages.some(x => x.uid === uid)) state.selected.delete(uid); // 1.7.0
    state.hasMore = res.hasMore;
    state.listOffline = !!res.offline;                     // 1.3.0
    if (res.offline && accId !== UNIFIED) setAccountOffline(accId, true);
    $('#folderCount').textContent = res.total ? `· ${res.total}` : '';
    if (accId !== UNIFIED) notifyNew(accId, folder, res.messages);
    renderList();
  } catch (e) {
    if (e.code === 'OFFLINE') setAccountOffline(accId, true);
    $('#messageList').innerHTML = `<div class="list-empty">${e.code === 'OFFLINE' ? '📴 ' : 'Could not load messages:<br>'}${esc(e.message)}</div>`;
  }
}

function notifyNew(accId, folder, msgs) {
  const key = accId + '|' + folder;
  const known = state.knownUids[key];
  state.knownUids[key] = new Set([...(known || []), ...msgs.map(m => m.uid)]);
  if (!known || !/inbox/i.test(folder)) return;
  // 1.2.0: when push is connected, the push event already notified about these
  if (['live', 'polling'].includes(state.push[accId])) return;
  const fresh = msgs.filter(m => !known.has(m.uid) && !m.seen);
  showMailNotifications(accId, fresh);
}

// Windows notification for up to 3 new unread messages; click opens the message
function showMailNotifications(accId, msgs) {
  if (state.settings.notifyNewMail === false) return;
  for (const m of msgs.slice(0, 3)) {
    try {
      const n = new Notification(addrShort(m.from[0]) || 'New message', { body: m.encrypted ? '🔒 Encrypted message' : m.subject });
      n.onclick = async () => {
        await call('appFocus');
        switchView('mail');
        if (state.cur.accId !== accId || state.cur.folder !== 'INBOX') { selectFolder(accId, 'INBOX'); await new Promise(r => setTimeout(r, 600)); }
        openMessage(m.uid);
      };
    } catch { /* notifications blocked */ }
  }
  if (msgs.length > 3) {
    try { new Notification('Sealpost', { body: `${msgs.length - 3} more new messages` }); } catch { /* ignore */ }
  }
}

/* ---------- 1.10.0: conversations ----------
 * With Conversation view on for an account, replies are grouped with the
 * message they answer (Message-ID / In-Reply-To / References, and a
 * "Re:" subject as a fallback). One line per conversation — click it to
 * open the newest message and show the others underneath. Off unless
 * turned on, per account (right-click the account name or the 💬 button). */
const convOn = accId => !!(state.accounts.find(a => a.id === accId) || {}).conversationView;
const REPLY_RE = /^\s*((re|fw|fwd|aw|sv|antw|wg|rv|tr)\s*(\[\d+\])?\s*:\s*)+/i;
function threadKeys(msgs) {
  const parent = new Map();
  const add = x => { if (!parent.has(x)) parent.set(x, x); };
  const find = x => { add(x); while (parent.get(x) !== x) { parent.set(x, parent.get(parent.get(x))); x = parent.get(x); } return x; };
  const union = (a, b) => { const ra = find(a), rb = find(b); if (ra !== rb) parent.set(ra, rb); };
  const bySubject = new Map();
  for (const m of msgs) {
    const me = 'm:' + m.uid, acc = (m.accId || state.cur.accId) + ':';
    add(me);
    if (m.messageId) union(me, 'id:' + acc + m.messageId);
    for (const r of [m.inReplyTo, ...(m.references || [])]) if (r) union(me, 'id:' + acc + r);
    const subj = String(m.subject || '').replace(REPLY_RE, '').trim().toLowerCase();
    if (subj.length > 3) {
      const k = acc + subj;
      if (!bySubject.has(k)) bySubject.set(k, []);
      bySubject.get(k).push({ me, reply: REPLY_RE.test(m.subject || '') });
    }
  }
  for (const group of bySubject.values()) if (group.length > 1 && group.some(x => x.reply)) for (const x of group.slice(1)) union(group[0].me, x.me);
  const out = new Map();
  for (const m of msgs) out.set(m.uid, find('m:' + m.uid));
  return out;
}

/** What the list shows: plain messages, conversation lines, and the messages of open conversations. */
function listRows() {
  const drafts = !isUnified() && isDraftsFolder(state.cur.accId, state.cur.folder);
  const conv = drafts ? [] : state.messages.filter(m => convOn(m.accId || state.cur.accId));
  if (!conv.length) return state.messages.map(m => ({ kind: 'msg', m }));
  const keyOf = threadKeys(conv);
  const groups = new Map();
  for (const m of conv) { const k = keyOf.get(m.uid); if (!groups.has(k)) groups.set(k, []); groups.get(k).push(m); }
  const rows = [], done = new Set();
  for (const m of state.messages) {
    if (!keyOf.has(m.uid)) { rows.push({ kind: 'msg', m }); continue; }
    const k = keyOf.get(m.uid);
    if (done.has(k)) continue;
    done.add(k);
    const t = groups.get(k);
    if (t.length === 1) { rows.push({ kind: 'msg', m }); continue; }
    rows.push({ kind: 'thread', key: k, m: t[0], msgs: t });
    if (state.expanded.has(k)) for (const c of t) rows.push({ kind: 'child', m: c, key: k });
  }
  return rows;
}

/** The 💬 button: conversation view for the open account. */
function updateConvButton() {
  const b = $('#btnConv');
  if (!b) return;
  const id = state.cur.accId;
  show(b, !!id && id !== UNIFIED);
  const on = id && id !== UNIFIED && convOn(id);
  b.classList.toggle('on', !!on);
  b.title = on ? 'Conversation view is on for this account — click to turn it off' : 'Group replies into conversations (this account)';
}

let dragInfo = null;   // 1.10.0: messages being dragged onto a folder

function renderList() {
  const list = $('#messageList');
  list.innerHTML = '';
  if (!state.messages.length) {
    list.innerHTML = `<div class="list-empty">${state.cur.search ? 'No messages match your search.' : 'This folder is empty.'}</div>`;
  }
  const isSentLike = !isUnified() && /sent|draft/i.test(state.cur.folder);
  const rows = listRows();
  state.visible = rows.filter(r => r.kind !== 'thread').map(r => r.m.uid);   // keyboard ↑/↓ order
  for (const row of rows) {
    const { m } = row;
    const t = row.kind === 'thread' ? row.msgs : null;
    const keys = t ? t.map(x => x.uid) : [m.uid];
    const unread = t ? t.some(x => !x.seen) : !m.seen;
    const allSel = keys.every(k => state.selected.has(k));
    const el = document.createElement('div');
    el.className = 'msg' + (unread ? ' unread' : '') + (row.kind === 'child' ? ' child' : '') + (t ? ' thread' + (state.expanded.has(row.key) ? ' open' : '') : '') +
      ((t ? keys.includes(state.selectedUid) && !state.expanded.has(row.key) : m.uid === state.selectedUid) ? ' active' : '') + (allSel ? ' selected' : '') +
      (state.listOffline && !m.cached ? ' not-saved' : '');               // 1.3.0: not readable offline
    if (state.listOffline && !m.cached) el.title = 'Not saved on this PC — readable when you\'re back online';
    el.dataset.uid = m.uid;
    let who = isSentLike ? 'To: ' + (m.to.map(addrShort).join(', ') || '—') : (m.from.map(addrShort).join(', ') || '—');
    if (t) {
      const names = [...new Set(t.slice().reverse().map(x => addrShort(x.from[0]) || '?'))];
      who = names.slice(0, 3).join(', ') + (names.length > 3 ? ` +${names.length - 3}` : '');
    }
    const acct = isUnified() ? (state.accounts.find(a => a.id === m.accId) || {}).email : '';
    const any = f => (t ? t.some(f) : f(m));
    const badges = [
      any(x => x.encrypted) ? '<span class="badge enc">🔒 ENCRYPTED</span>' : '',
      any(x => x.signed) ? '<span class="badge sig">✍ SIGNED</span>' : '',
      any(x => x.hasAttachments) ? '<span>📎</span>' : '',
      any(x => x.flagged) ? '<span style="color:var(--amber)">⚑</span>' : ''
    ].join('');
    el.innerHTML = `
      <input type="checkbox" class="sel-box" aria-label="Select"${allSel ? ' checked' : ''}>
      <button class="read-dot" title="${unread ? 'Mark as read' : 'Mark as unread'}" aria-label="${unread ? 'Mark as read' : 'Mark as unread'}"></button>
      <div class="top"><span class="from">${t ? `<span class="tw">${state.expanded.has(row.key) ? '▾' : '▸'}</span>` : ''}${esc(who)}${t ? ` <span class="tcount">${t.length}</span>` : ''}</span><span class="date">${esc(fmtDate(m.date))}</span></div>
      <div class="subj">${esc(m.subject)}<span class="badges">${badges}</span></div>${acct ? `<div class="acct-tag">${esc(acct)}</div>` : ''}`;
    // 1.6.0: the dot toggles read / unread (a whole conversation at once); right-click for more
    el.querySelector('.read-dot').onclick = e => { e.stopPropagation(); setSeen(keys, unread); };
    el.oncontextmenu = e => { e.preventDefault(); t ? threadMenu(e, t) : messageMenu(e, m); };
    // 1.10.0: drag onto a folder to move (drags the whole selection when this message is part of it)
    el.draggable = true;
    el.ondragstart = e => {
      const ks = keys.some(k => state.selected.has(k)) ? [...state.selected] : keys;
      dragInfo = { keys: ks, accIds: accountsOf(ks), folder: isUnified() ? 'INBOX' : state.cur.folder };
      e.dataTransfer.effectAllowed = 'move';
      e.dataTransfer.setData('text/plain', `${ks.length} message${ks.length === 1 ? '' : 's'}`);
    };
    el.ondragend = () => { dragInfo = null; $$('.folder.drop').forEach(x => x.classList.remove('drop')); };
    el.onclick = e => {
      // 1.7.0: tick box, Ctrl-click, Shift-click (and select mode) select instead of opening
      if (e.target.closest('.sel-box') || MOD(e) || e.shiftKey || state.selectMode || state.selected.size) {
        if (t) { const on = !allSel; for (const k of keys) on ? state.selected.add(k) : state.selected.delete(k); renderList(); return; }
        if (e.shiftKey && state.anchor != null) selectRange(state.anchor, m.uid); else toggleSelect(m.uid);
        return;
      }
      if (t) {   // conversation line: open it up and show the newest message
        if (state.expanded.has(row.key)) state.expanded.delete(row.key); else state.expanded.add(row.key);
        state.anchor = m.uid;
        if (state.expanded.has(row.key)) openMessage(m.uid); else renderList();
        return;
      }
      state.anchor = m.uid;
      !isUnified() && isDraftsFolder(state.cur.accId, state.cur.folder) ? openDraftFromList(m.uid) : openMessage(m.uid);
    };
    list.appendChild(el);
  }
  show($('#btnMore'), state.hasMore);
  renderBulkBar(); // 1.7.0
}

function threadMenu(e, t) {
  const keys = t.map(x => x.uid), unread = t.some(x => !x.seen);
  showMenu(e, [
    { label: unread ? '○ Mark conversation as read' : '● Mark conversation as unread', run: () => setSeen(keys, unread) },
    { label: '☐ Select conversation', run: () => { keys.forEach(k => state.selected.add(k)); renderList(); } },
    '-',
    { label: '🗑 Delete conversation', danger: true, run: () => bulkDelete(keys) }
  ]);
}

/* ---------- 6f. Selecting several messages (1.7.0) ---------- */
function toggleSelect(uid) {
  if (state.selected.has(uid)) state.selected.delete(uid); else state.selected.add(uid);
  state.anchor = uid;
  renderList();
}
function selectRange(a, b) {
  const ia = state.messages.findIndex(m => m.uid === a), ib = state.messages.findIndex(m => m.uid === b);
  if (ia < 0 || ib < 0) return toggleSelect(b);
  for (let i = Math.min(ia, ib); i <= Math.max(ia, ib); i++) state.selected.add(state.messages[i].uid);
  renderList();
}
function selectAll() { state.messages.forEach(m => state.selected.add(m.uid)); renderList(); }
function clearSelection() { state.selected.clear(); state.selectMode = false; renderList(); }

function renderBulkBar() {
  const n = state.selected.size;
  const on = n > 0 || state.selectMode;
  $('#messageList').classList.toggle('selecting', on);
  $('#btnSelectMode').classList.toggle('on', on);
  show($('#bulkBar'), on);
  $('#bulkCount').textContent = n ? `${n} selected` : 'Tick messages';
  $$('#bulkBar [data-bulk]').forEach(b => { if (!['all', 'clear'].includes(b.dataset.bulk)) b.disabled = !n; });
  const sel = $('#bulkMove');
  // 1.10.0: in All Inboxes, moving works when the selection is from one account
  const accs = accountsOf([...state.selected]);
  const moveAcc = isUnified() ? (accs.size === 1 ? [...accs][0] : null) : state.cur.accId;
  sel.disabled = !n || !moveAcc;
  sel.title = moveAcc ? '' : 'Select messages from one account to move them';
  sel.innerHTML = '<option value="">Move to…</option>' + (state.folders[moveAcc] || [])
    .filter(f => f.path !== (isUnified() ? 'INBOX' : state.cur.folder))
    .map(f => `<option value="${esc(f.path)}"${f.noselect ? ' disabled' : ''}>${'\u00a0'.repeat((f.depth || 0) * 3)}${esc(f.name)}</option>`).join('');
}

$('#btnConv').addEventListener('click', () => { if (state.cur.accId && !isUnified()) setConversation(state.cur.accId, !convOn(state.cur.accId)); });   // 1.10.0

$('#btnSelectMode').addEventListener('click', () => {
  if (state.selectMode || state.selected.size) clearSelection();
  else { state.selectMode = true; renderList(); }
});

$$('#bulkBar [data-bulk]').forEach(b => b.addEventListener('click', async () => {
  const act = b.dataset.bulk;
  if (act === 'all') return selectAll();
  if (act === 'clear') return clearSelection();
  const uids = [...state.selected];
  if (!uids.length) return;
  try {
    if (act === 'read' || act === 'unread') { await setSeen(uids, act === 'read'); toast(`${uids.length} marked as ${act}.`); }
    if (act === 'flag') {
      const on = !uids.every(u => (state.messages.find(m => m.uid === u) || {}).flagged);
      await perBox(uids, (a, f, u) => call('mailFlag', a, f, u, '\\Flagged', on));
      for (const m of state.messages) if (uids.includes(m.uid)) m.flagged = on;
      renderList();
      toast(`${uids.length} ${on ? 'flagged' : 'unflagged'}.`);
    }
    if (act === 'delete') await bulkDelete(uids);
  } catch (e) { toast(e.message, 'err'); }
}));

async function bulkDelete(uids) {
  const f = (state.folders[state.cur.accId] || []).find(x => x.path === state.cur.folder);
  const inTrash = f && f.specialUse === '\\Trash';
  if (!(await confirmBox('Delete messages', inTrash ? `Delete ${uids.length} message(s) permanently?` : `Move ${uids.length} message(s) to Trash?`, 'Delete', true))) return;
  try {
    await perBox(uids, (a, fo, u) => call('mailDelete', a, fo, u));   // 1.10.0
    removeMany(uids);
    toast(`${uids.length} ${inTrash ? 'deleted' : 'moved to Trash'}.`);
  } catch (e) { toast(e.message, 'err'); }
}

$('#bulkMove').addEventListener('change', async e => {
  const to = e.target.value;
  e.target.value = '';
  const uids = [...state.selected];
  if (!to || !uids.length) return;
  const accs = [...accountsOf(uids)];
  if (accs.length === 1) moveMessages(uids, accs[0], to);
});

/** 1.10.0: move messages (from the Move list or dragged onto a folder). */
async function moveMessages(keys, accId, to) {
  keys = [].concat(keys);
  if (!keys.length) return;
  try {
    await perBox(keys, (a, f, u) => (a === accId && f !== to ? call('mailMove', a, f, u, to) : null));
    removeMany(keys);
    toast(`${keys.length} moved to ${((state.folders[accId] || []).find(f => f.path === to) || {}).name || to}.`);
    loadFolders(accId);
  } catch (err) { toast(err.message, 'err'); }
}

/** Take several messages out of the list (moved / deleted). */
function removeMany(uids) {
  const set = new Set(uids);
  const accs = accountsOf(uids);   // (before the messages leave the list)
  state.messages = state.messages.filter(m => !set.has(m.uid));
  if (set.has(state.selectedUid)) closeReader();
  state.selected.clear(); state.selectMode = false;
  renderList();
  for (const a of accs) loadFolders(a);
}

$('#btnMore').addEventListener('click', () => { state.cur.page++; loadMessages({ append: true }); });

/* ---------- 6d. Read / unread (1.6.0) ---------- */
/** Mark messages in the open folder read (on=true) or unread. */
async function setSeen(uids, on) {
  try {
    const accs = accountsOf(uids);
    const rs = await perBox(uids, (a, f, u) => call('mailFlag', a, f, u, '\\Seen', on));   // 1.10.0: per account
    const r = rs.find(x => x && x.queued);
    for (const m of state.messages) if (uids.includes(m.uid)) m.seen = on;
    renderList();
    updateReadButton();
    for (const a of accs) loadFolders(a);
    if (r && r.queued) toast('Changed on this PC — the server is updated when you\'re back online.', 'warn');
  } catch (e) { toast(e.message, 'err'); }
}

/** Mark every unread message in a folder as read. */
async function markFolderRead(accId, folder) {
  if (accId === UNIFIED) {   // 1.10.0: every Inbox
    let n = 0;
    for (const a of state.accounts) { try { const r = await call('mailMarkFolderRead', a.id, 'INBOX'); n += r.count || 0; } catch (e) { toast(a.email + ': ' + e.message, 'err'); } loadFolders(a.id); }
    if (isUnified()) { for (const m of state.messages) m.seen = true; renderList(); updateReadButton(); }
    return toast(n ? `Marked ${n} message${n === 1 ? '' : 's'} as read.` : 'Everything here is already read.');
  }
  try {
    const r = await call('mailMarkFolderRead', accId, folder);
    if (accId === state.cur.accId && folder === state.cur.folder) { for (const m of state.messages) m.seen = true; renderList(); updateReadButton(); }
    const f = (state.folders[accId] || []).find(x => x.path === folder);
    if (f) { f.unseen = 0; renderTree(); }
    loadFolders(accId);
    toast(r.count ? `Marked ${r.count} message${r.count === 1 ? '' : 's'} as read${r.queued ? ' (the server is updated when you\'re back online)' : ''}.` : 'Everything here is already read.');
  } catch (e) { toast(e.message, 'err'); }
}
$('#btnMarkAllRead').addEventListener('click', () => state.cur.accId && markFolderRead(state.cur.accId, state.cur.folder));

/** The reader's read/unread button shows what clicking it will do. */
function updateReadButton() {
  const b = $('[data-act=unread]');
  const m = state.messages.find(x => x.uid === state.selectedUid);
  const seen = !m || m.seen;
  b.textContent = seen ? '●' : '○';
  b.title = seen ? 'Mark unread (Ctrl+U)' : 'Mark read (Ctrl+Q)';
}

/* ---------- 6e. Right-click menus (1.6.0) ---------- */
function showMenu(e, items) {
  const menu = $('#ctxMenu');
  menu.innerHTML = '';
  for (const it of items) {
    if (it === '-') { const hr = document.createElement('div'); hr.className = 'ctx-sep'; menu.appendChild(hr); continue; }
    const b = document.createElement('button');
    b.className = 'ctx-item' + (it.danger ? ' danger' : '');
    b.textContent = it.label;
    b.onclick = () => { hideMenu(); it.run(); };
    menu.appendChild(b);
  }
  show(menu, true);
  const w = menu.offsetWidth, h = menu.offsetHeight;
  menu.style.left = Math.min(e.clientX, innerWidth - w - 8) + 'px';
  menu.style.top = Math.min(e.clientY, innerHeight - h - 8) + 'px';
  setTimeout(() => menu.querySelector('button')?.focus(), 0);
}
function hideMenu() { show($('#ctxMenu'), false); }
document.addEventListener('mousedown', e => { if (!e.target.closest('#ctxMenu')) hideMenu(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') hideMenu(); }, true);
window.addEventListener('blur', hideMenu);

function messageMenu(e, m) {
  showMenu(e, [
    { label: m.seen ? '● Mark as unread' : '○ Mark as read', run: () => setSeen([m.uid], !m.seen) },
    { label: m.flagged ? '⚑ Remove flag' : '⚑ Flag', run: async () => {
      try { await perBox([m.uid], (a, f, u) => call('mailFlag', a, f, u, '\\Flagged', !m.flagged)); m.flagged = !m.flagged; renderList(); }
      catch (err) { toast(err.message, 'err'); }
    } },
    '-',
    { label: '✓ Mark all in this folder as read', run: () => markFolderRead(state.cur.accId, state.cur.folder) }
  ]);
}
$('#btnRefresh').addEventListener('click', refreshAll);
let searchTimer;
$('#searchBox').addEventListener('input', e => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => { state.cur.search = e.target.value.trim(); state.cur.page = 0; loadMessages(); }, 450);
});

async function refreshAll() {
  if (!state.cur.accId) return;
  state.cur.page = 0;
  await loadMessages({ silent: true });
  loadFolders(state.cur.accId);
}

/* ---------- 6b. Instant new mail (1.2.0) ----------
 * The main process keeps an IDLE connection per account and sends:
 *   status  -> connection state for the indicator next to the folder name
 *   new     -> new unread messages in INBOX (refresh + notification)
 *   changed -> something was read/flagged/deleted elsewhere (refresh)
 * A slow safety check still runs: every 10 min when push is live,
 * every 2 min when it isn't. */
state.push = {};
let lastRefresh = Date.now();

window.api.onEvent(({ type, data }) => {
  if (type === 'status') { state.push[data.accId] = data.state; renderPushStatus(); return; }
  const isCurrentInbox = (data.accId === state.cur.accId || isUnified()) && /^inbox$/i.test(state.cur.folder) && !state.cur.search && state.cur.page === 0;
  if (type === 'new') {
    const key = data.accId + '|INBOX';
    state.knownUids[key] = new Set([...(state.knownUids[key] || []), ...data.messages.map(m => m.uid)]);
    showMailNotifications(data.accId, data.messages);
    if (isCurrentInbox) { loadMessages({ silent: true }); lastRefresh = Date.now(); }
    loadFolders(data.accId); // unread counts
  }
  if (type === 'changed') {
    clearTimeout(window.__chgTimer);
    window.__chgTimer = setTimeout(() => { if (isCurrentInbox) loadMessages({ silent: true }); loadFolders(data.accId); }, 800);
  }
});

function renderPushStatus() {
  const el = $('#pushStatus');
  const st = state.settings.pushMail === false ? null : state.push[state.cur.accId];
  if (!st) return show(el, false);
  const label = { live: '● Live', polling: '● Auto-checking', connecting: '● Connecting…', offline: '● Offline — retrying' }[st] || st;
  const tip = {
    live: 'Instant new mail is on: the server tells Sealpost the moment mail arrives.',
    polling: 'This server doesn\'t support instant push; Sealpost checks quietly in the background.',
    connecting: 'Connecting for instant new mail…',
    offline: 'Lost the connection to the mail server. Sealpost keeps retrying automatically.'
  }[st] || '';
  el.textContent = label; el.title = tip;
  el.className = 'push-status ' + st;
  show(el, true);
}

setInterval(() => {
  if (!state.cur.accId || state.cur.search || state.cur.page !== 0) return;
  const live = ['live', 'polling'].includes(state.push[state.cur.accId]);
  if (Date.now() - lastRefresh >= (live ? 600000 : 120000)) { lastRefresh = Date.now(); refreshAll(); }
}, 30000);

/* =================================================================
 * 6c. OFFLINE MAIL + OUTBOX (1.3.0)
 * ================================================================= */
state.offlineAcc = new Set();

function setAccountOffline(accId, off) {
  if (off) state.offlineAcc.add(accId); else state.offlineAcc.delete(accId);
  show($('#offlineBar'), state.offlineAcc.has(state.cur.accId));
}

window.api.onEvent(({ type, data }) => {
  if (type === 'net') {
    const wasOff = state.offlineAcc.has(data.accId);
    setAccountOffline(data.accId, data.offline);
    if (wasOff && !data.offline) {
      toast('Back online');
      if (data.accId === state.cur.accId || isUnified()) { loadMessages({ silent: true }); loadFolders(data.accId); }
    }
  }
  if (type === 'outbox') {
    refreshOutbox();
    if (data.sent) toast(`📤 Outbox: ${data.sent} message${data.sent === 1 ? '' : 's'} sent`);
  }
  if (type === 'sync' && $('#view-settings').classList.contains('active')) renderOfflinePanel();
});

async function refreshOutbox() {
  let st;
  try { st = await call('offlineStatus'); } catch { return; }
  state.offline = st;
  const n = (st.outbox || 0) + (st.drafts || 0);
  show($('#btnOutbox'), n > 0);
  $('#outboxCount').textContent = n;
}

$('#btnOutbox').addEventListener('click', openOutbox);

async function openOutbox() {
  const r = await call('outboxList');
  const accName = id => (state.accounts.find(a => a.id === id) || {}).email || '';
  const html = `
    <p class="muted small">Messages here were finished while you were offline. They're already ${'encrypted/signed as you chose'} and go out automatically when the connection returns.</p>
    ${r.outbox.length ? '' : '<p class="muted">The Outbox is empty.</p>'}
    <div id="obList">${r.outbox.map(o => `
      <div class="outbox-item" data-id="${esc(o.id)}">
        <div class="info">
          <div><b>${esc(o.summary.subject || '(no subject)')}</b> ${o.summary.encrypted ? '<span class="badge enc">🔒</span>' : ''}${o.summary.signed ? ' <span class="badge sig">✍</span>' : ''}</div>
          <div class="muted small">To ${esc(o.summary.to || '')} · from ${esc(accName(o.accId))} · queued ${esc(new Date(o.queued).toLocaleString())}</div>
          ${o.error ? `<div class="error small">Server refused it: ${esc(o.error)}</div>` : ''}
        </div>
        <button class="btn small danger" data-del="${esc(o.id)}">Delete</button>
      </div>`).join('')}</div>
    ${r.drafts.length ? `<h3>Drafts saved on this PC</h3>${r.drafts.map(d => `
      <div class="outbox-item">
        <div class="info"><div><b>${esc(d.summary.subject || '(no subject)')}</b></div>
          <div class="muted small">To ${esc(d.summary.to || '—')} · saved ${esc(new Date(d.saved).toLocaleString())} · uploads to Drafts when online</div></div>
        <button class="btn small" data-open="${esc(d.id)}">Open</button>
      </div>`).join('')}` : ''}`;
  const p = dialog({ title: '📤 Outbox', html, okText: 'Send now', cancelText: 'Close' });
  $$('#dlgBody [data-del]').forEach(b => b.onclick = async () => {
    if (!(await confirmBox('Delete message', 'Delete this unsent message? It will not be sent.', 'Delete', true))) return openOutbox();
    await call('outboxDelete', b.dataset.del); refreshOutbox(); openOutbox();
  });
  $$('#dlgBody [data-open]').forEach(b => b.onclick = async () => {
    $('#dlgModal')._cancel();
    try { const d = await call('draftsOpenLocal', b.dataset.open); await openComposer({ draft: d }); } catch (e) { toast(e.message, 'err'); }
  });
  if (await p) {
    const res = await call('outboxSendNow');
    refreshOutbox();
    if (res.waiting) toast(`${res.waiting} message(s) still waiting — still offline?`, 'warn');
  }
}

/* ---------- Settings panel ---------- */
const fmtMB = b => b >= 1073741824 ? (b / 1073741824).toFixed(1) + ' GB' : Math.max(0.1, b / 1048576).toFixed(1) + ' MB';

async function renderOfflinePanel() {
  const body = $('#offlinePanelBody');
  let st;
  try { st = await call('offlineStatus'); } catch { return; }
  state.offline = st;
  if (!st.lockEnabled) {
    body.innerHTML = `<p class="small">Offline mail needs <b>App lock</b>, because the offline copy is encrypted to your PIN.</p>`;
    const b = document.createElement('button'); b.className = 'btn'; b.textContent = 'Turn on app lock first…'; b.onclick = setupLockDialog;
    body.appendChild(b); return;
  }
  if (!st.enabled || !st.exists) {
    body.innerHTML = '';
    const b = document.createElement('button'); b.className = 'btn primary'; b.textContent = 'Turn on offline mail…'; b.onclick = enableOfflineDialog;
    body.appendChild(b); return;
  }
  const pct = Math.min(100, Math.round(st.usage / (st.capMB * 1048576) * 100));
  body.innerHTML = `
    <p>✅ Offline mail is <b>on</b>${st.open ? '' : ' (locked — unlock Sealpost with your PIN)'}.</p>
    <div class="small">Using <b>${fmtMB(st.usage)}</b> of ${st.capMB >= 1024 ? st.capMB / 1024 + ' GB' : st.capMB + ' MB'}</div>
    <div class="usage-bar"><span style="width:${pct}%"></span></div>
    <div class="small muted">${st.syncing ? '⟳ Saving mail…' : st.lastSync ? 'Last saved ' + esc(new Date(st.lastSync).toLocaleTimeString()) : 'Not saved yet'}
      ${st.outbox ? ` · ${st.outbox} in Outbox` : ''}${st.pending ? ` · ${st.pending} change(s) waiting` : ''}</div>
    <div class="kv2">
      <label>Keep mail from the last</label>
      <select id="ofDays"><option value="7">7 days</option><option value="30">30 days</option><option value="90">90 days</option><option value="365">1 year</option></select>
      <label>Save messages up to</label>
      <select id="ofMax"><option value="5">5 MB</option><option value="10">10 MB</option><option value="25">25 MB</option><option value="50">50 MB</option></select>
      <label>Use at most</label>
      <select id="ofCap"><option value="250">250 MB</option><option value="500">500 MB</option><option value="1024">1 GB</option><option value="2048">2 GB</option><option value="5120">5 GB</option></select>
    </div>
    <p class="muted small">Bigger messages are saved when you open them. When the limit is reached, the oldest saved messages are removed first.</p>
    <div class="row gap wrap">
      <button class="btn small" id="ofSync">⟳ Save now</button>
      <button class="btn small" id="ofClear">Clear saved mail</button>
      <button class="btn small danger" id="ofOff">Turn off…</button>
    </div>`;
  $('#ofDays').value = String(st.days); $('#ofMax').value = String(st.maxMsgMB); $('#ofCap').value = String(st.capMB);
  const upd = async () => { await call('offlineUpdate', { days: $('#ofDays').value, maxMsgMB: $('#ofMax').value, capMB: $('#ofCap').value }); toast('Offline mail updated'); renderOfflinePanel(); };
  ['#ofDays', '#ofMax', '#ofCap'].forEach(id => $(id).onchange = upd);
  $('#ofSync').onclick = async () => { $('#ofSync').disabled = true; $('#ofSync').textContent = '⟳ Saving…'; try { await call('offlineSyncNow'); } catch (e) { toast(e.message, 'err'); } renderOfflinePanel(); };
  $('#ofClear').onclick = async () => {
    if (!(await confirmBox('Clear saved mail', 'Remove the saved copies of your mail from this PC? The Outbox and unsent changes are kept. Mail is saved again in the background.', 'Clear'))) return;
    await call('offlineClear'); toast('Saved mail cleared'); renderOfflinePanel();
  };
  $('#ofOff').onclick = async () => {
    if (!(await confirmBox('Turn off offline mail', 'Delete the offline copy from this PC and stop saving mail?', 'Turn off', true))) return;
    try { await call('offlineDisable'); toast('Offline mail turned off'); } catch (e) { toast(e.message, 'err'); }
    renderOfflinePanel(); renderLockPanel();
  };
}

async function enableOfflineDialog() {
  await dialog({
    title: 'Turn on offline mail',
    html: `<p>Sealpost will keep an encrypted copy of recent mail on this PC.</p>
      <ul class="small">
        <li>The copy is encrypted to your <b>app-lock PIN</b> — it can only be opened by unlocking Sealpost with that PIN (or with a key passphrase via "Forgot PIN").</li>
        <li>PGP-encrypted mail stays PGP-encrypted inside the copy.</li>
        ${PLATFORM === 'win32' ? `<li><b>Windows Hello unlock is turned off</b> while offline mail is on — Hello can't provide the PIN the copy needs.</li>` : ''}
        <li><b>Use a long PIN.</b> Anyone who copies this PC's files could try to guess it. Each guess takes about a second, so 8 or more digits keeps the copy safe for years; 6 digits is the minimum.</li>
      </ul>
      <label>Your app-lock PIN</label><input type="password" inputmode="numeric" id="ofPin">
      <div class="kv2">
        <label>Keep mail from the last</label>
        <select id="ofDays2"><option value="7">7 days</option><option value="30" selected>30 days</option><option value="90">90 days</option><option value="365">1 year</option></select>
        <label>Save messages up to</label>
        <select id="ofMax2"><option value="5">5 MB</option><option value="10" selected>10 MB</option><option value="25">25 MB</option><option value="50">50 MB</option></select>
        <label>Use at most</label>
        <select id="ofCap2"><option value="250">250 MB</option><option value="500" selected>500 MB</option><option value="1024">1 GB</option><option value="2048">2 GB</option><option value="5120">5 GB</option></select>
      </div>
      <p id="ofErr" class="error"></p>`,
    okText: 'Turn on',
    onOk: async () => {
      $('#ofErr').textContent = 'Setting up…'; $('#dlgOk').disabled = true;
      const r = await window.api.offlineEnable({ pin: $('#ofPin').value, days: $('#ofDays2').value, maxMsgMB: $('#ofMax2').value, capMB: $('#ofCap2').value });
      $('#dlgOk').disabled = false;
      if (!r.ok) { $('#ofErr').textContent = r.error; return false; }
      toast('Offline mail is on — saving your mail in the background');
      return true;
    }
  });
  renderOfflinePanel(); renderLockPanel();
}

/* =================================================================
 * 7. READER
 * ================================================================= */
function closeReader() {
  state.selectedUid = null;
  state.view = null;
  show($('#reader'), false);
  show($('#readerEmpty'), true);
}

async function openMessage(uid) {
  state.selectedUid = uid;
  renderList();   // 1.10.0 (conversations: highlight the right line)
  show($('#readerEmpty'), false);
  show($('#reader'), true);
  $('#rSubject').textContent = 'Loading…';
  $('#textBody').textContent = '';
  show($('#htmlBody'), false);
  $('#pgpBanner').innerHTML = '';
  $('#attachments').innerHTML = '';
  try {
    const l = loc(uid);   // 1.10.0: the message's own account + folder
    const v = await call('mailOpen', l.accId, l.folder, l.uid);
    if (state.selectedUid !== uid) return;
    Object.assign(v, { accId: l.accId, folder: l.folder, uid: l.uid });
    state.view = v;
    const m = state.messages.find(x => x.uid === uid);
    if (m && !m.seen) { m.seen = true; renderList(); loadFolders(l.accId); }
    renderMessage(v);
  } catch (e) {
    $('#rSubject').textContent = 'Could not open message';
    $('#textBody').textContent = e.message;
  }
}

function renderMessage(v) {
  $('#rSubject').textContent = v.subject || '(no subject)';
  $('#rFrom').textContent = v.from.map(addr).join(', ');
  $('#rTo').textContent = v.to.map(addr).join(', ') || '—';
  $('#rCc').textContent = v.cc.map(addr).join(', ');
  show($('#rCcRow'), v.cc.length > 0);
  $('#rDate').textContent = fmtDate(v.date, true);
  const flagged = state.messages.find(x => x.uid === state.selectedUid)?.flagged;
  $('[data-act=flag]').classList.toggle('on', !!flagged);
  updateReadButton(); // 1.6.0
  renderMoveSelect();
  renderPgpBanner(v);
  renderAttachments(v);
  renderBody(v, v.html ? 'html' : 'text');
}

/* ---------- 7a. PGP status banner ---------- */
function renderPgpBanner(v) {
  const p = v.pgp;
  const box = $('#pgpBanner');
  box.innerHTML = '';
  const add = (kind, ico, html) => {
    const d = document.createElement('div');
    d.className = 'pgp-banner ' + kind;
    d.innerHTML = `<span class="ico">${ico}</span><div class="msg-txt">${html}</div>`;
    box.appendChild(d);
    return d;
  };

  if (p.needPassphrase) {
    const d = add('info', '🔒', `<b>Encrypted message.</b> Unlock your key to read it.<div class="sub">${esc(p.needPassphrase.userId || '')}</div>`);
    const b = document.createElement('button');
    b.className = 'btn primary small'; b.textContent = 'Unlock & decrypt';
    b.onclick = async () => { if (await promptPassphrase(p.needPassphrase.fingerprint, p.needPassphrase.userId)) openMessage(state.selectedUid); };
    d.appendChild(b);
  } else if (p.encrypted && p.decrypted) {
    add('ok', '🔒', `<b>Decrypted.</b> This message was end-to-end encrypted${p.inline ? ' (inline PGP)' : ''}.${p.protectedSubject ? ' The subject was protected too.' : ''}`);
  } else if (p.encrypted && !p.decrypted) {
    add('bad', '⛔', `<b>Could not decrypt this message.</b><div class="sub">${esc(p.errors.join(' · '))}</div>`);
  }

  for (const s of p.signatures) {
    if (s.valid) {
      const trusted = s.trust === 'verified' || s.trust === 'ultimate';
      const mismatch = !s.matchesSender;
      add(mismatch ? 'warn' : 'ok', mismatch ? '⚠' : '✔',
        `<b>Good signature</b> from ${esc(s.signer)}` +
        (mismatch ? ' — <b>but the signer’s key does not match the From address.</b>' : '') +
        (trusted ? '' : ' <span class="muted">(key not yet marked as verified — compare the fingerprint with the sender)</span>') +
        `<div class="sub">${esc(s.fingerprint || s.keyId)}</div>`);
    } else if (s.unknownKey && v.sender && v.sender.status === 'key-changed') {
      continue; // the key-change warning below explains this signature (1.1.0)
    } else if (s.unknownKey) {
      const d = add('warn', '?', `<b>Signed with a key you don't have</b> (ID ${esc(s.keyId)}). The signature can't be checked yet.`);
      const b = document.createElement('button');
      b.className = 'btn small'; b.textContent = 'Find sender key';
      b.onclick = () => lookupDialog(v.from[0]?.address || '');
      d.appendChild(b);
    } else {
      add('bad', '✖', `<b>BAD SIGNATURE.</b> The message was altered or the signature is forged.<div class="sub">${esc(s.signer || s.keyId)} — ${esc(s.error || '')}</div>`);
    }
  }
  if (p.signed && !p.signatures.length && !p.needPassphrase && p.decrypted !== false) {
    add('warn', '⚠', '<b>Signature present but could not be checked.</b>' + (p.errors.length ? `<div class="sub">${esc(p.errors.join(' · '))}</div>` : ''));
  }
  for (const n of p.notes) add('warn', 'ℹ', esc(n));

  /* ---------- 1.1.0: sender / contact key check ---------- */
  const s = v.sender;
  const actBtn = (box, label, fn, cls = 'btn small') => { const b = document.createElement('button'); b.className = cls; b.textContent = label; b.style.marginLeft = '6px'; b.onclick = fn; box.appendChild(b); };
  const fromMessage = async action => {
    try { v.sender = await call('contactsFromMessage', v.key, action); renderPgpBanner(v); toast('Contact updated'); }
    catch (e) { toast(e.message, 'err'); }
  };
  if (s && s.status === 'key-changed') {
    const d = add('bad', '⚠', `<b>Key change for ${esc(s.contact.name || s.email)}.</b> This message was signed with, or offers, a different key than the one assigned to this contact.
      That can mean they made a new key — or that someone is impersonating them. Confirm with them (phone, in person) before switching.
      <div class="sub">Assigned: ${esc(s.contact.keyFp || '')}<br>This message: ${esc(s.changedTo || '')}</div>`);
    actBtn(d, 'Use new key…', async () => {
      if (!(await confirmBox('Switch key', `Assign the new key to ${s.contact.name || s.email}? Only do this if you have confirmed it with them.`, 'Use new key', true))) return;
      fromMessage('pin');
    }, 'btn small danger');
    actBtn(d, 'Open contact', () => openContact(s.contact.id));
  } else if (s && s.status === 'offer-assign') {
    const d = add('info', '🔑', `${esc(s.contact.name || s.email)} is a contact without a key. This message ${s.candidateInKeyring ? 'was signed with' : 'includes'} a key for them.`);
    actBtn(d, 'Assign key to contact', () => fromMessage('pin'), 'btn small primary');
  } else if (s && s.status === 'offer-add') {
    const d = add('info', '👤', `${esc(s.name || s.email)} isn't in your contacts. This message ${s.candidateInKeyring ? 'was signed with' : 'includes'} their key.`);
    actBtn(d, 'Add contact with key', () => fromMessage('pin'), 'btn small primary');
  } else if (v.autocryptKey && !(s && s.status === 'ok')) {
    const d = add('info', '🔑', 'The sender included their public key (Autocrypt).');
    const b = document.createElement('button');
    b.className = 'btn small'; b.textContent = 'Import key';
    b.onclick = async () => { try { const r = await call('mailImportAutocrypt', v.key); toast(importSummary(r)); } catch (e) { toast(e.message, 'err'); } };
    d.appendChild(b);
  }
}

/* ---------- 7b. Attachments ---------- */
function renderAttachments(v) {
  const box = $('#attachments');
  box.innerHTML = '';
  for (const a of v.attachments.filter(a => !a.inline || !v.html)) {
    const el = document.createElement('div');
    el.className = 'att';
    el.innerHTML = `<span>${a.isKey ? '🔑' : a.isEncrypted ? '🔒' : '📄'}</span><span class="att-name" title="${esc(a.filename)}">${esc(a.filename)}</span><span class="att-size">${fmtSize(a.size)}</span>`;
    const btn = (label, fn) => { const b = document.createElement('button'); b.className = 'btn small'; b.textContent = label; b.onclick = fn; el.appendChild(b); };
    if (a.isKey) btn('Import key', async () => { try { toast(importSummary(await call('attImportKey', v.key, a.index))); } catch (e) { toast(e.message, 'err'); } });
    if (a.isEncrypted) btn('Decrypt & save', async () => {
      try { const r = await call('attDecrypt', v.key, a.index); if (r.saved) toast('Decrypted file saved to ' + r.saved); } catch (e) { if (e.code !== 'CANCELLED') toast(e.message, 'err'); }
    });
    btn('Open', async () => {
      if (!(await confirmBox('Open attachment', `Open "${a.filename}" with its default Windows program? Only open files you trust.`, 'Open'))) return;
      try { await call('attOpen', v.key, a.index); } catch (e) { toast(e.message, 'err'); }
    });
    btn('Save', async () => { try { const p = await call('attSave', v.key, a.index); if (p) toast('Saved to ' + p); } catch (e) { toast(e.message, 'err'); } });
    box.appendChild(el);
  }
}

/* ---------- 7c. Body (sandboxed HTML or plain text) ---------- */
let remoteAllowedFor = null;

// Creates a fresh sandboxed iframe holding the email's HTML (no scripts allowed)
function makeHtmlFrame(doc) {
  const f = document.createElement('iframe');
  f.id = 'htmlBody';
  f.title = 'Message body';
  f.setAttribute('sandbox', 'allow-popups allow-popups-to-escape-sandbox');
  f.srcdoc = doc;
  return f;
}

function renderBody(v, mode) {
  const hasHtml = !!v.html;
  show($('#bodyToggle'), hasHtml);
  $$('#bodyToggle button').forEach(b => b.classList.toggle('primary', b.dataset.mode === mode));
  if (mode === 'html' && hasHtml) {
    const allowRemote = state.settings.loadRemoteImages || remoteAllowedFor === v.key;
    const hasRemote = /<img[^>]+src=["']?https?:|url\(["']?https?:/i.test(v.html);
    show($('#remoteBar'), hasRemote && !allowRemote);
    // The iframe is sandboxed (no scripts, no same-origin) and gets its own CSP.
    const csp = `default-src 'none'; style-src 'unsafe-inline'; font-src data:; img-src data: ${allowRemote ? 'https: http:' : ''};`;
    const doc =
      `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="${csp}">` +
      `<base target="_blank"><style>body{font-family:Segoe UI,system-ui,sans-serif;font-size:14px;color:#111;margin:14px;word-wrap:break-word}img{max-width:100%;height:auto}</style></head><body>` +
      v.html + '</body></html>';
    show($('#textBody'), false);
    // FIX 1.0.1: build a brand-new frame for every message. Re-using one frame that
    // was hidden (e.g. while the message was still locked, then decrypted in place)
    // could leave it blank white in Chromium.
    $('#htmlBody').replaceWith(makeHtmlFrame(doc));
  } else {
    show($('#remoteBar'), false);
    $('#htmlBody').replaceWith(makeHtmlFrame(''));
    show($('#htmlBody'), false);
    show($('#textBody'), true);
    const t = $('#textBody');
    t.innerHTML = '';
    // render quoted lines dimmed, and make links clickable (safely)
    for (const line of (v.text || '').split('\n')) {
      const span = document.createElement('span');
      if (/^\s*>/.test(line)) span.className = 'quote';
      linkify(span, line);
      t.appendChild(span);
      if (!span.className) t.appendChild(document.createTextNode('\n'));
    }
  }
}

function linkify(parent, text) {
  const re = /\bhttps?:\/\/[^\s<>"')]+/g;
  let last = 0, m;
  while ((m = re.exec(text))) {
    parent.appendChild(document.createTextNode(text.slice(last, m.index)));
    const a = document.createElement('a');
    a.href = '#'; a.textContent = m[0]; a.style.color = 'var(--blue)';
    const url = m[0];
    a.onclick = e => { e.preventDefault(); call('shellOpenExternal', url); };
    parent.appendChild(a);
    last = m.index + m[0].length;
  }
  parent.appendChild(document.createTextNode(text.slice(last)));
}

$$('#bodyToggle button').forEach(b => b.addEventListener('click', () => state.view && renderBody(state.view, b.dataset.mode)));
$('#btnLoadImages').addEventListener('click', () => { remoteAllowedFor = state.view.key; renderBody(state.view, 'html'); });

/* ---------- 7d. Reader actions ---------- */
function renderMoveSelect() {
  const sel = $('#moveSelect');
  sel.innerHTML = '<option value="">Move to…</option>';
  const l = state.selectedUid != null ? loc(state.selectedUid) : { accId: state.cur.accId, folder: state.cur.folder };
  for (const f of state.folders[l.accId] || []) {
    if (f.path === l.folder) continue;
    const o = document.createElement('option');
    o.value = f.path; o.textContent = '\u00a0'.repeat((f.depth || 0) * 3) + f.name;   // 1.9.1: indented like the folder list
    o.disabled = !!f.noselect;
    sel.appendChild(o);
  }
}

$('#moveSelect').addEventListener('change', async e => {
  const target = e.target.value;
  if (!target || !state.selectedUid) return;
  try {
    const l = loc(state.selectedUid);
    await call('mailMove', l.accId, l.folder, l.uid, target);
    removeFromList(state.selectedUid);
    toast('Moved to ' + target);
  } catch (err) { toast(err.message, 'err'); }
});

function removeFromList(uid) {
  const acc = loc(uid).accId;
  const order = state.visible && state.visible.length ? state.visible : state.messages.map(m => m.uid);
  const i = order.indexOf(uid);
  state.messages = state.messages.filter(m => m.uid !== uid);
  renderList();
  const nextKey = [order[i + 1], order[i - 1]].find(k => k != null && state.messages.some(m => m.uid === k));
  if (nextKey != null) openMessage(nextKey); else closeReader();
  loadFolders(acc);
}

async function deleteSelected() {
  if (!state.selectedUid) return;
  try {
    const l = loc(state.selectedUid);
    await call('mailDelete', l.accId, l.folder, l.uid);
    removeFromList(state.selectedUid);
  } catch (e) { toast(e.message, 'err'); }
}

$$('.reader-actions [data-act]').forEach(b => b.addEventListener('click', async () => {
  const act = b.dataset.act, v = state.view;
  if (!v) return;
  const m = state.messages.find(x => x.uid === state.selectedUid);
  try {
    if (act === 'reply' || act === 'replyAll' || act === 'forward') openComposer({ mode: act, view: v });
    if (act === 'delete') deleteSelected();
    if (act === 'addContact') {
      const r = await call('contactsFromMessage', v.key, 'contact-only');
      v.sender = r; renderPgpBanner(v);
      toast(`${r.contact ? (r.contact.name || r.email) : r.email} is in your contacts`);
    }
    if (act === 'flag') {
      const on = !(m && m.flagged);
      const l = loc(state.selectedUid);
      await call('mailFlag', l.accId, l.folder, l.uid, '\\Flagged', on);
      if (m) m.flagged = on;
      b.classList.toggle('on', on);
      renderList();
    }
    if (act === 'unread') {   // 1.6.0: toggles read / unread
      const on = !(m ? m.seen : true);
      await setSeen([state.selectedUid], on);
      toast(on ? 'Marked as read' : 'Marked as unread');
    }
    if (act === 'source') {
      const src = await call('mailSource', v.key);
      dialog({ title: 'Message source', html: `<textarea readonly style="width:100%;min-height:60vh">${esc(src)}</textarea>`, hideCancel: true, okText: 'Close' });
    }
  } catch (e) { toast(e.message, 'err'); }
}));

/* =================================================================
 * 8. COMPOSER  (rewritten in 1.1.0)
 *   8a. State + open/close (new, reply, forward, reopen draft)
 *   8b. Rich text editor (toolbar, safe paste, plain <-> rich)
 *   8c. Address autocomplete from Contacts
 *   8d. Recipient key status + per-contact rules
 *   8e. Attachments
 *   8f. Drafts (encrypted autosave to the server's Drafts folder)
 *   8g. Send
 * ================================================================= */
const compose = {
  attachments: [], reply: null,
  draft: null,          // { accId, folder, uid } of the saved draft
  dirty: false,         // changed since last draft save
  touched: {},          // encrypt/sign toggled by hand -> contact rules stop overriding
  saving: false
};

/* ---------- 8a. Open / close ---------- */
const escHtml = s => esc(s).replace(/\n/g, '<br>');

/* ---------- 1.9.0: "Send as" helpers ----------
 * fromChoice(): what the From list says -> { accId, fromAddress (alias or
 * null), email (the address that will show as From) } */
function fromChoice() {
  const v = $('#cFrom').value || '';
  const i = v.indexOf('|');
  const accId = i < 0 ? v : v.slice(0, i);
  const fromAddress = i < 0 ? null : v.slice(i + 1);
  const acct = state.accounts.find(a => a.id === accId);
  return { accId, fromAddress, email: fromAddress || (acct && acct.email) || '', acct };
}
/** Which of this account's "Send as" addresses the message was sent to (for replies). */
function aliasAddressedIn(view, accId) {
  const acct = state.accounts.find(a => a.id === accId);
  if (!acct || !(acct.aliases || []).length) return null;
  const got = [...(view.to || []), ...(view.cc || [])].map(x => (x.address || '').toLowerCase());
  if (got.includes(acct.email.toLowerCase())) return null;
  const hit = acct.aliases.find(a => got.includes(a.email.toLowerCase()));
  return hit ? hit.email : null;
}

async function openComposer({ mode = 'new', view = null, to = '', draft = null } = {}) {
  if (!state.accounts.length) { toast('Add an email account first (Settings).', 'warn'); return switchView('settings'); }
  Object.assign(compose, { attachments: [], reply: null, draft: null, dirty: false, touched: {} });

  // 1.9.0: each account plus its "Send as" addresses; option value "accId" or "accId|alias@address"
  const from = $('#cFrom');
  from.innerHTML = '';
  for (const a of state.accounts) {
    const o = document.createElement('option');
    o.value = a.id; o.textContent = a.name ? `${a.name} <${a.email}>` : a.email;
    from.appendChild(o);
    for (const al of a.aliases || []) {
      const x = document.createElement('option');
      x.value = a.id + '|' + al.email;
      x.textContent = `${al.name || a.name ? (al.name || a.name) + ' ' : ''}<${al.email}>  · send as`;
      from.appendChild(x);
    }
  }
  const baseAcc = (draft && draft.accId) || (view && view.accId) || (state.cur.accId !== UNIFIED && state.cur.accId) || state.accounts[0].id;   // 1.10.0
  from.value = baseAcc;
  // a draft keeps its address; a reply/forward uses the address the message was sent to
  const wantAlias = draft ? draft.meta?.fromAddress : view ? aliasAddressedIn(view, baseAcc) : null;
  if (wantAlias && [...from.options].some(o => o.value === baseAcc + '|' + wantAlias)) from.value = baseAcc + '|' + wantAlias;
  const acct = state.accounts.find(a => a.id === baseAcc);

  const rich = draft ? draft.meta?.format === 'rich' : state.settings.composeFormat === 'rich';
  let subject = '', toList = to, ccList = '', bccList = '';
  let text = '', html = '';
  const sigText = acct?.signature ? '\n\n-- \n' + acct.signature : '';
  const sigHtml = acct?.signature ? '<br><br>-- <br>' + escHtml(acct.signature) : '';

  if (draft) {
    // reopening a saved draft
    toList = draft.to; ccList = draft.cc; bccList = draft.bcc; subject = draft.subject;
    text = draft.text || ''; html = draft.html || '';
    compose.draft = { accId: draft.accId, folder: draft.folder, uid: draft.uid };
    compose.attachments = (draft.attachments || []).map(a => ({ name: a.filename, size: a.size, content: a.content, contentType: a.contentType }));
    const m = draft.meta || {};
    if (m.inReplyTo) compose.reply = { inReplyTo: m.inReplyTo, references: m.references, uid: m.replyToUid, folder: m.replyFolder };
  } else if (view) {
    const header = (view.date ? `On ${fmtDate(view.date, true)}, ` : '') + `${addr(view.from[0])} wrote:`;
    const original = (view.text || '').trimEnd();
    if (mode === 'forward') {
      subject = /^fwd?:/i.test(view.subject) ? view.subject : 'Fwd: ' + view.subject;
      const fwdHead = `---------- Forwarded message ----------\nFrom: ${view.from.map(addr).join(', ')}\nDate: ${fmtDate(view.date, true)}\nSubject: ${view.subject}\nTo: ${view.to.map(addr).join(', ')}`;
      text = `${sigText}\n\n${fwdHead}\n\n${original}`;
      html = `<p><br></p>${sigHtml}<p><br></p><div>${escHtml(fwdHead)}<br><br>${escHtml(original)}</div>`;
    } else {
      subject = /^re:/i.test(view.subject) ? view.subject : 'Re: ' + view.subject;
      const replyTo = view.replyTo.length ? view.replyTo : view.from;
      toList = replyTo.map(addr).join(', ');
      if (mode === 'replyAll') {
        const me = state.accounts.flatMap(a => [a.email, ...(a.aliases || []).map(x => x.email)]).map(e => e.toLowerCase());   // 1.9.0
        const others = [...view.to, ...view.cc].filter(x => !me.includes((x.address || '').toLowerCase()) && !replyTo.some(r => r.address === x.address));
        ccList = others.map(addr).join(', ');
      }
      text = `${sigText}\n\n${header}\n${original.split('\n').map(l => '> ' + l).join('\n')}`;
      // the original is quoted as escaped text — never pasted as live HTML
      html = `<p><br></p>${sigHtml}<p><br></p><div>${esc(header)}</div><blockquote>${escHtml(original)}</blockquote>`;
      compose.reply = { inReplyTo: view.messageId, references: [view.references, view.messageId].filter(Boolean).join(' '), uid: view.uid ?? state.selectedUid, folder: view.folder || state.cur.folder };
    }
  } else {
    text = sigText;
    html = sigHtml ? `<p><br></p>${sigHtml}` : '<p><br></p>';
  }

  $('#composeTitle').textContent = draft ? 'Draft' : { new: 'New message', reply: 'Reply', replyAll: 'Reply all', forward: 'Forward' }[mode];
  $('#cTo').value = toList || '';
  $('#cCc').value = ccList || '';
  $('#cBcc').value = bccList || '';
  $('#cSubject').value = subject || '';
  setRich(rich, { text, html: html || escHtml(text) });

  const m = draft && draft.meta;
  $('#cSign').checked = m ? !!m.sign : !!state.settings.defaultSign;
  $('#cEncrypt').checked = m ? !!m.encrypt : (!!(view && view.pgp && view.pgp.encrypted) || !!state.settings.defaultEncrypt);
  $('#cHideSubject').checked = m ? !!m.hideSubject : false;
  $('#cAttachKey').checked = m ? !!m.attachPublicKey : !!state.settings.attachPublicKey;
  if (m) compose.touched = { encrypt: true, sign: true }; // keep the draft's own choices
  $('#cDraftStatus').textContent = draft ? (draft.encrypted ? '🔒 Encrypted draft' : 'Draft') : '';
  renderComposeAttachments();
  openModal('#composeModal');
  await updateKeyStatus(true);
  setTimeout(() => {
    if (!$('#cTo').value) $('#cTo').focus();
    else if (isRich()) { $('#cEditor').focus(); placeCaretAtStart($('#cEditor')); }
    else { $('#cBody').focus(); $('#cBody').setSelectionRange(0, 0); }
  }, 50);
}

// Close: save the draft (if anything was written) unless the user discards
async function closeComposer() {
  hideAc();
  const empty = !composeRecipients().length && !$('#cSubject').value.trim() && !bodyPlain().trim() && !compose.attachments.length;
  if (empty && !compose.draft) return closeModal('#composeModal');
  const choice = await dialog({
    title: 'Close message',
    html: '<p>Save this message as a draft so you can finish it later?</p><p class="muted small">Drafts are encrypted to your own key before being stored on your mail server.</p>',
    okText: 'Save draft', cancelText: 'Keep writing', extraText: 'Discard'
  });
  if (choice === 'extra') return discardComposer(true);
  if (!choice) return; // keep writing
  clearTimeout(draftTimer);
  if (compose.dirty || !compose.draft) await saveDraftNow(true);
  closeModal('#composeModal');
}

async function discardComposer(confirmed = false) {
  setTimeout(refreshOutbox, 800); // 1.3.0
  if (!confirmed && !(await confirmBox('Discard message', 'Delete this message' + (compose.draft ? ' and its saved draft' : '') + '?', 'Discard', true))) return;
  clearTimeout(draftTimer);
  if (compose.draft) { try { await call('draftsDelete', compose.draft.accId, compose.draft.folder, compose.draft.uid); } catch { /* ignore */ } }
  compose.draft = null; compose.dirty = false;
  closeModal('#composeModal');
  refreshIfDraftsFolder();
}
$('#cClose').addEventListener('click', closeComposer);
$('#cDiscard').addEventListener('click', () => discardComposer());

/* ---------- 8b. Rich text editor ---------- */
const isRich = () => $('#cRich').checked;

function setRich(on, { text, html } = {}) {
  $('#cRich').checked = on;
  $('#cToolbar').classList.toggle('plain', !on);
  show($('#cEditor'), on);
  show($('#cBody'), !on);
  if (on) $('#cEditor').innerHTML = sanitizeHtml(html != null ? html : escHtml(text || ''));
  else $('#cBody').value = text != null ? text : '';
}

function bodyPlain() { return isRich() ? $('#cEditor').innerText : $('#cBody').value; }

$('#cRich').addEventListener('change', async () => {
  if (isRich()) {
    // plain -> rich: keep the text, turn line breaks into HTML
    setRich(true, { html: escHtml($('#cBody').value) });
  } else {
    const hasFormatting = /<(b|strong|i|em|u|s|ul|ol|font|span|a|blockquote|h\d)\b/i.test($('#cEditor').innerHTML);
    if (hasFormatting && !(await confirmBox('Switch to plain text', 'Formatting (bold, lists, colors, links) will be removed. Continue?', 'Switch'))) {
      $('#cRich').checked = true; return;
    }
    setRich(false, { text: $('#cEditor').innerText.replace(/\n{3,}/g, '\n\n') });
  }
  markDirty();
});

function placeCaretAtStart(el) {
  const r = document.createRange(); r.setStart(el, 0); r.collapse(true);
  const sel = window.getSelection(); sel.removeAllRanges(); sel.addRange(r);
}

// Toolbar commands (document.execCommand still works in Chromium/Electron)
$$('#cToolbar [data-cmd]').forEach(b => b.addEventListener('mousedown', e => {
  e.preventDefault(); // keep the selection in the editor
  const cmd = b.dataset.cmd;
  $('#cEditor').focus();
  if (cmd === 'quote') document.execCommand('formatBlock', false, 'blockquote');
  else if (cmd === 'foreColorApply') document.execCommand('foreColor', false, $('#cColor').value);
  else if (cmd === 'link') {
    const sel = window.getSelection();
    const range = sel.rangeCount ? sel.getRangeAt(0).cloneRange() : null;
    dialog({
      title: 'Insert link', okText: 'Insert',
      html: '<label>Web address</label><input type="text" id="lnkUrl" placeholder="https://"><p id="lnkErr" class="error"></p>',
      onOk: () => {
        let url = $('#lnkUrl').value.trim();
        if (!/^(https?:|mailto:)/i.test(url)) url = 'https://' + url;
        if (!/^(https?:\/\/[^\s]+|mailto:[^\s]+)$/i.test(url)) { $('#lnkErr').textContent = 'Enter a web or mailto: address'; return false; }
        $('#cEditor').focus();
        if (range) { sel.removeAllRanges(); sel.addRange(range); }
        if (range && !range.collapsed) document.execCommand('createLink', false, url);
        else document.execCommand('insertHTML', false, `<a href="${esc(url)}">${esc(url)}</a>`);
        markDirty();
        return true;
      }
    });
    return;
  } else document.execCommand(cmd, false, null);
  updateToolbarState();
  markDirty();
}));
$('#cFontSize').addEventListener('change', e => {
  if (!e.target.value) return;
  $('#cEditor').focus();
  document.execCommand('fontSize', false, e.target.value);
  e.target.value = '';
  markDirty();
});
$('#cColor').addEventListener('input', e => { $('#cColorBar').style.background = e.target.value; });
$('#cColorBar').style.background = $('#cColor').value;

function updateToolbarState() {
  for (const c of ['bold', 'italic', 'underline', 'strikeThrough', 'insertUnorderedList', 'insertOrderedList']) {
    const b = $(`#cToolbar [data-cmd="${c}"]`);
    try { b.classList.toggle('on', document.queryCommandState(c)); } catch { /* ignore */ }
  }
}
document.addEventListener('selectionchange', () => { if (document.activeElement === $('#cEditor')) updateToolbarState(); });

// Pasted HTML is cleaned: no scripts, no remote images, only basic formatting
const ALLOWED_TAGS = new Set(['B', 'STRONG', 'I', 'EM', 'U', 'S', 'STRIKE', 'P', 'DIV', 'BR', 'UL', 'OL', 'LI', 'BLOCKQUOTE', 'A', 'SPAN', 'FONT', 'H1', 'H2', 'H3', 'H4', 'PRE', 'CODE', 'TABLE', 'THEAD', 'TBODY', 'TR', 'TD', 'TH', 'SUB', 'SUP', 'HR']);
const ALLOWED_STYLES = ['color', 'background-color', 'font-weight', 'font-style', 'text-decoration', 'font-size', 'text-align'];

function sanitizeHtml(html) {
  const doc = new DOMParser().parseFromString(`<div>${html || ''}</div>`, 'text/html');
  const root = doc.body.firstChild;
  (function clean(node) {
    for (const child of [...node.childNodes]) {
      if (child.nodeType === 3) continue;                       // text
      if (child.nodeType !== 1) { child.remove(); continue; }   // comments etc.
      if (!ALLOWED_TAGS.has(child.tagName)) {
        if (['SCRIPT', 'STYLE', 'IFRAME', 'OBJECT', 'EMBED', 'IMG', 'SVG', 'VIDEO', 'AUDIO', 'TITLE', 'META', 'LINK', 'HEAD'].includes(child.tagName)) { child.remove(); continue; }
        clean(child);
        child.replaceWith(...child.childNodes);                 // unwrap unknown tags, keep their text
        continue;
      }
      for (const attr of [...child.attributes]) {
        const n = attr.name.toLowerCase();
        if (n === 'href' && child.tagName === 'A' && /^(https?:|mailto:)/i.test(attr.value.trim())) continue;
        if (n === 'style') {
          const kept = ALLOWED_STYLES.map(p => child.style.getPropertyValue(p) ? `${p}: ${child.style.getPropertyValue(p)}` : '').filter(Boolean).join('; ');
          if (kept) { child.setAttribute('style', kept); continue; }
        }
        if (child.tagName === 'FONT' && (n === 'color' || n === 'size')) continue;
        if (['colspan', 'rowspan'].includes(n)) continue;
        child.removeAttribute(attr.name);
      }
      clean(child);
    }
  })(root);
  return root.innerHTML;
}

$('#cEditor').addEventListener('paste', e => {
  const html = e.clipboardData.getData('text/html');
  const text = e.clipboardData.getData('text/plain');
  e.preventDefault();
  if (html) document.execCommand('insertHTML', false, sanitizeHtml(html));
  else document.execCommand('insertHTML', false, escHtml(text));
  markDirty();
});
$('#cEditor').addEventListener('drop', e => e.preventDefault()); // no dragged-in images/HTML
$('#cEditor').addEventListener('input', markDirty);
$('#cEditor').addEventListener('click', e => { if (e.target.closest('a')) e.preventDefault(); }); // don't navigate while editing
$('#cBody').addEventListener('input', markDirty);
$('#cSubject').addEventListener('input', markDirty);

/* ---------- 8c. Address autocomplete ---------- */
let acField = null, acItems = [], acSel = 0, acTimer;

function currentToken(input) {
  const v = input.value, pos = input.selectionStart;
  const start = v.lastIndexOf(',', pos - 1) + 1;
  return { start, end: pos, text: v.slice(start, pos).trim() };
}

function hideAc() { show($('#acBox'), false); acField = null; acItems = []; }

async function showAc(input) {
  const tok = currentToken(input);
  if (tok.text.length < 1 || tok.text.includes('<')) return hideAc();
  let res = [];
  try { res = await call('contactsSearch', tok.text); } catch { /* ignore */ }
  const already = composeRecipients();
  res = res.filter(r => !already.includes(r.email));
  if (!res.length) return hideAc();
  acField = input; acItems = res; acSel = 0;
  const box = $('#acBox');
  box.innerHTML = '';
  res.forEach((r, i) => {
    const el = document.createElement('div');
    el.className = 'ac-item' + (i === 0 ? ' sel' : '');
    el.innerHTML = `<span class="ac-lock" title="${r.hasKey ? 'Has a PGP key' : 'No key'}">${r.hasKey ? '🔒' : ''}</span><span>${esc(r.name || r.email)}</span>${r.name ? `<span class="ac-email">${esc(r.email)}</span>` : ''}`;
    el.onmousedown = e => { e.preventDefault(); pickAc(i); };
    box.appendChild(el);
  });
  const rect = input.getBoundingClientRect();
  Object.assign(box.style, { left: rect.left + 'px', top: rect.bottom + 2 + 'px', width: rect.width + 'px' });
  show(box, true);
}

function pickAc(i) {
  const r = acItems[i], input = acField;
  if (!r || !input) return;
  const tok = currentToken(input);
  const entry = r.name ? `${r.name.replace(/[",<>]/g, '')} <${r.email}>` : r.email;
  const before = input.value.slice(0, tok.start).trim();
  const after = input.value.slice(tok.end).replace(/^[^,]*/, '');
  input.value = (before ? before + ' ' : '') + entry + ', ' + after.replace(/^,\s*/, '');
  hideAc();
  input.focus();
  markDirty();
  updateKeyStatus();
}

$$('.addr-input').forEach(input => {
  input.addEventListener('input', () => { clearTimeout(acTimer); acTimer = setTimeout(() => showAc(input), 120); markDirty(); clearTimeout(keyStatusTimer); keyStatusTimer = setTimeout(updateKeyStatus, 500); });
  input.addEventListener('keydown', e => {
    if ($('#acBox').classList.contains('hidden') || acField !== input) return;
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      acSel = (acSel + (e.key === 'ArrowDown' ? 1 : -1) + acItems.length) % acItems.length;
      $$('.ac-item').forEach((el, i) => el.classList.toggle('sel', i === acSel));
    } else if (e.key === 'Enter' || e.key === 'Tab') { e.preventDefault(); pickAc(acSel); }
    else if (e.key === 'Escape') { e.stopPropagation(); hideAc(); }
  });
  input.addEventListener('blur', () => setTimeout(() => { if (acField === input) hideAc(); }, 150));
});

/* ---------- 8d. Recipient key status + contact rules ---------- */
function composeRecipients() {
  return ['#cTo', '#cCc', '#cBcc']
    .flatMap(id => $(id).value.split(/[,;]/))
    .map(s => { const m = s.match(/<([^>]+)>/); return (m ? m[1] : s).trim().toLowerCase(); })
    .filter(s => /.+@.+\..+/.test(s));
}

let keyStatusTimer;
async function updateKeyStatus(initial = false) {
  const emails = [...new Set(composeRecipients())];
  const box = $('#cKeyStatus');
  const { acct, email: fromEmail, fromAddress } = fromChoice();   // 1.9.0
  let mine = null, fallback = null;
  try { mine = fromEmail ? await call('pgpSecretFor', fromEmail) : null; } catch { /* ignore */ }
  if (!mine && fromAddress && acct) { try { fallback = await call('pgpSecretFor', acct.email); } catch { /* ignore */ } }
  box.innerHTML = '';
  if (!mine) {
    const c = document.createElement('span');
    c.className = 'key-chip ' + (fallback ? 'info' : 'missing');
    // a "Send as" address without its own key signs with the account's key
    c.textContent = fallback ? `Signing as ${fromEmail} with your ${acct.email} key — click to create a key for ${fromEmail}` : `No private key for ${fromEmail} — click to create one`;
    const al = fromAddress && acct ? (acct.aliases || []).find(x => x.email === fromAddress) : null;
    c.onclick = () => openGenerate((al && al.name) || acct?.name, fromEmail);
    box.appendChild(c);
  }
  if (!emails.length) { $('#cHint').textContent = ''; return; }
  let st = {};
  try { st = await call('pgpRecipientStatus', emails); } catch { return; }

  let allOk = true, wantEncrypt = false, signRule = null, viaAddy = false;
  for (const e of emails) {
    const s = st[e] || {};
    // 1.13.0: an addy.io address is shown as the real recipient its key belongs to
    if (s.keyAddress) viaAddy = true;
    const who = (s.contact && s.contact.name ? `${s.contact.name}` : s.keyAddress || e) + (s.keyAddress ? ' (via addy.io)' : '');
    const c = document.createElement('span');
    if (s.ok) {
      c.className = 'key-chip ok';
      c.innerHTML = `🔑 ${esc(who)}${s.verified ? ' <span class="ver" title="Fingerprint verified">✔</span>' : ''}`;
      c.title = `${e}${s.keyAddress ? `\nThrough addy.io to ${s.keyAddress} — encrypted to their key` : ''}\nKey ${s.fingerprint}${s.pinned ? '\n(assigned in Contacts)' : ''}`;
    } else {
      allOk = false;
      c.className = 'key-chip missing';
      const why = { expired: 'key expired', revoked: 'key revoked', missing: 'assigned key missing', unusable: 'key unusable' }[s.problem] || 'no key';
      c.textContent = `⚠ ${why}: ${who}`;
      c.title = 'Click to search for this person\'s key online';
      c.onclick = () => lookupDialog(e, () => updateKeyStatus());
    }
    box.appendChild(c);
    if (s.otherKey) {
      // a DIFFERENT key exists for this address than the one assigned
      const w = document.createElement('span');
      w.className = 'key-chip changed';
      w.textContent = `⚠ ${who}: another key exists`;
      w.title = 'A different key for this address is in your keyring. Sealpost keeps using the key assigned in Contacts. Click to review.';
      w.onclick = () => { closeModal('#composeModal'); openContact(s.contact && s.contact.id); };
      box.appendChild(w);
    }
    if (s.contact) {
      if (s.contact.encrypt === 'always') wantEncrypt = true;
      if (s.contact.sign === 'never') signRule = 'never';
      else if (s.contact.sign === 'always' && signRule !== 'never') signRule = 'always';
    }
  }
  // contact rules apply unless you changed the toggle yourself
  if (!compose.touched.encrypt) {
    if (wantEncrypt) $('#cEncrypt').checked = true;
    else if (initial && state.settings.defaultEncrypt) $('#cEncrypt').checked = allOk;
  }
  if (!compose.touched.sign && signRule) $('#cSign').checked = signRule === 'always';
  $('#cHint').textContent = [
    $('#cEncrypt').checked && !allOk ? 'Some recipients have no usable key — encryption will fail.' : '',
    // 1.13.0: addy.io hides your address, but the message itself can still name your key
    viaAddy && ($('#cSign').checked || $('#cAttachKey').checked) ? 'Through addy.io they see your alias, but a signature or attached key shows the addresses on your key.' : ''
  ].filter(Boolean).join(' ');
}
$('#cFrom').addEventListener('change', () => { updateKeyStatus(); markDirty(); });
$('#cEncrypt').addEventListener('change', () => { compose.touched.encrypt = true; updateKeyStatus(); markDirty(); });
$('#cSign').addEventListener('change', () => { compose.touched.sign = true; markDirty(); updateKeyStatus(); });
['#cHideSubject', '#cAttachKey'].forEach(id => $(id).addEventListener('change', markDirty));
$('#cAttachKey').addEventListener('change', () => updateKeyStatus());   // 1.13.0: addy.io hint

/* ---------- 8e. Attachments ---------- */
function renderComposeAttachments() {
  const box = $('#cAttachments');
  box.innerHTML = '';
  compose.attachments.forEach((a, i) => {
    const c = document.createElement('span');
    c.className = 'chip';
    c.innerHTML = `📎 ${esc(a.name)} <span class="muted">${fmtSize(a.size)}</span>`;
    const x = document.createElement('button'); x.textContent = '✕';
    x.onclick = () => { compose.attachments.splice(i, 1); renderComposeAttachments(); markDirty(); };
    c.appendChild(x);
    box.appendChild(c);
  });
}

$('#cAttach').addEventListener('click', async () => {
  const files = await call('dialogPickFiles');
  compose.attachments.push(...files);
  renderComposeAttachments();
  if (files.length) markDirty();
});

const attachmentPayload = () => compose.attachments.map(a => a.path ? { path: a.path } : { filename: a.name, content: a.content, contentType: a.contentType });

function draftPayload() {
  const rich = isRich();
  return {
    to: $('#cTo').value, cc: $('#cCc').value, bcc: $('#cBcc').value,
    subject: $('#cSubject').value,
    text: rich ? '' : $('#cBody').value,
    html: rich ? sanitizeHtml($('#cEditor').innerHTML) : null,
    encrypt: $('#cEncrypt').checked, sign: $('#cSign').checked,
    hideSubject: $('#cHideSubject').checked && $('#cEncrypt').checked,
    attachPublicKey: $('#cAttachKey').checked,
    attachments: attachmentPayload(),
    inReplyTo: compose.reply?.inReplyTo, references: compose.reply?.references,
    replyToUid: compose.reply?.uid, replyFolder: compose.reply?.folder,
    fromAddress: fromChoice().fromAddress      // 1.9.0: "Send as" address (null = the account's own)
  };
}

/* ---------- 8f. Drafts: autosave a few seconds after you stop typing ---------- */
let draftTimer;
function markDirty() {
  if ($('#composeModal').classList.contains('hidden')) return;
  compose.dirty = true;
  clearTimeout(draftTimer);
  draftTimer = setTimeout(() => saveDraftNow(), 5000);
}

async function saveDraftNow(final = false) {
  if (compose.saving) { if (final) await new Promise(r => setTimeout(r, 400)); else return; }
  const accId = fromChoice().accId;
  if (!accId) return;
  compose.saving = true;
  compose.dirty = false;
  $('#cDraftStatus').textContent = 'Saving draft…';
  try {
    // switched the From account? the old account's draft is removed
    let prev = compose.draft;
    if (prev && prev.accId !== accId) {
      try { await call('draftsDelete', prev.accId, prev.folder, prev.uid); } catch { /* ignore */ }
      prev = null;
    }
    const r = await call('draftsSave', accId, draftPayload(), prev);
    compose.draft = { accId, folder: r.folder, uid: r.uid };
    $('#cDraftStatus').textContent = (r.local ? '📴 Draft saved on this PC (offline) ' : r.encrypted ? '🔒 Encrypted draft saved ' : 'Draft saved (not encrypted — no key of your own) ') +
      new Date().toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
    refreshIfDraftsFolder();
    if (r.local) refreshOutbox(); // 1.3.0: offline drafts show in the Outbox count
  } catch (e) {
    compose.dirty = true;
    $('#cDraftStatus').textContent = 'Draft not saved: ' + e.message;
  } finally { compose.saving = false; }
}

function isDraftsFolder(accId, folder) {
  const f = (state.folders[accId] || []).find(x => x.path === folder);
  return !!(f && f.specialUse === '\\Drafts') || /^(inbox[./])?drafts?$/i.test(folder || '');
}
function refreshIfDraftsFolder() {
  if (isDraftsFolder(state.cur.accId, state.cur.folder)) loadMessages({ silent: true });
}

// Opening a message inside the Drafts folder reopens it in the composer
async function openDraftFromList(uid) {
  try {
    const d = await call('draftsOpen', state.cur.accId, state.cur.folder, uid);
    await openComposer({ draft: { ...d, accId: state.cur.accId } });
  } catch (e) { if (e.code !== 'CANCELLED') toast('Could not open draft: ' + e.message, 'err'); }
}

/* ---------- 8g. Send ---------- */
$('#cSend').addEventListener('click', sendMessage);

async function sendMessage() {
  const accId = fromChoice().accId;
  hideAc();
  const draft = draftPayload();
  if (!composeRecipients().length) return toast('Add at least one recipient', 'warn');
  if (!draft.subject && !(await confirmBox('No subject', 'Send without a subject?', 'Send'))) return;
  if (!bodyPlain().trim() && !compose.attachments.length && !(await confirmBox('Empty message', 'Send a message with no text?', 'Send'))) return;
  clearTimeout(draftTimer);
  if (compose.draft && compose.draft.accId === accId) { draft.draftUid = compose.draft.uid; draft.draftFolder = compose.draft.folder; }
  const btn = $('#cSend');
  btn.disabled = true; btn.textContent = draft.encrypt ? 'Encrypting & sending…' : 'Sending…';
  try {
    const sent = await call('mailSend', accId, draft);
    if (sent && sent.queued) {                                            // 1.3.0: offline -> Outbox
      compose.draft = null; compose.dirty = false;
      closeModal('#composeModal');
      toast('📤 You\'re offline — the message is ' + (draft.encrypt ? 'encrypted and ' : '') + 'waiting in the Outbox. It will send automatically when you\'re back online.', 'warn');
      refreshOutbox();
      return;
    }
    // a draft from another account (From was changed) is cleaned up too
    if (compose.draft && compose.draft.accId !== accId) { try { await call('draftsDelete', compose.draft.accId, compose.draft.folder, compose.draft.uid); } catch { /* ignore */ } }
    compose.draft = null; compose.dirty = false;
    closeModal('#composeModal');
    toast(draft.encrypt ? '🔒 Encrypted message sent' : draft.sign ? '✍ Signed message sent' : 'Message sent');
    if ((compose.reply && (accId === state.cur.accId || isUnified())) || isDraftsFolder(state.cur.accId, state.cur.folder)) loadMessages({ silent: true });
  } catch (e) {
    if (e.code === 'MISSING_KEYS') {
      toast('Missing public keys for: ' + e.missing.join(', ') + '. Click the amber chips to find them, or turn off Encrypt.', 'err');
      updateKeyStatus();
    } else if (e.code !== 'CANCELLED') toast('Send failed: ' + e.message, 'err');
    markDirty();
  } finally {
    btn.disabled = false; btn.textContent = 'Send';
  }
}

$('#btnCompose').addEventListener('click', () => openComposer());

/* =================================================================
 * 9. KEY MANAGER
 * ================================================================= */
async function loadKeys() {
  try { state.keys = await call('pgpList'); } catch (e) { toast(e.message, 'err'); state.keys = []; }
  checkExpiry(false);
  renderKeyList();
  if (state.selectedKey) {
    const k = state.keys.find(x => x.fingerprint === state.selectedKey);
    if (k) renderKeyDetail(k); else $('#keyDetail').innerHTML = '<div class="empty-state small"><p>Select a key to see details.</p></div>';
  }
}

function keyBadges(k) {
  return [
    k.hasPrivate ? '<span class="badge enc">YOUR KEY</span>' : '<span class="badge plain">PUBLIC</span>',
    k.revoked ? '<span class="badge bad">REVOKED</span>' : '',
    k.expired ? '<span class="badge bad">EXPIRED</span>' : '',
    k.trust === 'verified' ? '<span class="badge sig">✔ VERIFIED</span>' : '',
    k.trust === 'untrusted' ? '<span class="badge bad">DISTRUSTED</span>' : '',
    k.hasPrivate && k.unlocked ? '<span class="badge warn">UNLOCKED</span>' : '',
    k.passphraseRemembered ? '<span class="badge sig">🔑 AUTO-UNLOCK</span>' : '',
    k.passphraseSynced ? '<span class="badge sig">🔑 ALL DEVICES</span>' : ''
  ].join('');
}

function renderKeyList() {
  const q = $('#keyFilter').value.trim().toLowerCase();
  const list = $('#keyList');
  list.innerHTML = '';
  const keys = state.keys.filter(k => !q || k.userIds.join(' ').toLowerCase().includes(q) || k.fingerprint.toLowerCase().includes(q.replace(/\s/g, '')));
  if (!keys.length) list.innerHTML = `<div class="empty-state small"><p>${state.keys.length ? 'No keys match.' : 'Your keyring is empty. Generate your own key pair to get started.'}</p></div>`;
  for (const k of keys) {
    const el = document.createElement('div');
    el.className = 'key-row' + (k.fingerprint === state.selectedKey ? ' active' : '');
    el.innerHTML = `<div class="uid">${esc(k.userIds[0] || '(no user id)')}</div>
      <div class="kid">${esc(k.keyId.replace(/(.{4})/g, '$1 '))} · ${esc(k.algorithm)}</div>
      <div class="badges">${keyBadges(k)}</div>`;
    el.onclick = () => { state.selectedKey = k.fingerprint; renderKeyList(); renderKeyDetail(k); };
    list.appendChild(el);
  }
}
$('#keyFilter').addEventListener('input', renderKeyList);

function renderKeyDetail(k) {
  const d = $('#keyDetail');
  d.innerHTML = `
    <h3 style="margin-top:0">${esc(k.userIds[0] || '')}</h3>
    <div class="badges">${keyBadges(k)}</div>
    <div class="kv">
      <span class="k">Fingerprint</span><span class="fp">${esc(k.fingerprintPretty)}</span>
      <span class="k">User IDs</span><span>${k.userIds.map(esc).join('<br>')}</span>
      <span class="k">Algorithm</span><span>${esc(k.algorithm)}</span>
      <span class="k">Created</span><span>${esc(new Date(k.created).toLocaleDateString())}</span>
      <span class="k">Expires</span><span>${k.expires ? esc(new Date(k.expires).toLocaleDateString()) + (k.expired ? ' (expired)' : '') : 'Never'}</span>
      <span class="k">Can encrypt</span><span>${k.canEncrypt ? 'Yes' : 'No'}</span>
      <span class="k">Can sign</span><span>${k.canSign ? 'Yes' : 'No'}</span>
      <span class="k">Trust</span><span>${k.hasPrivate ? 'Your own key' : `
        <select id="kTrust" style="width:auto">
          <option value="unknown">Unknown — not checked</option>
          <option value="verified">Verified — I compared the fingerprint</option>
          <option value="untrusted">Do not trust</option>
        </select>`}</span>
    </div>
    <div class="key-actions" id="kActions"></div>
    ${k.hasPrivate ? `<div class="sync-pass">
      <label class="check"><input type="checkbox" id="kSyncPass" ${k.passphraseSynced ? 'checked' : ''}> Remember passphrase on all my devices</label>
      <p class="muted small" id="kSyncPassNote">Your other PCs and Sealpost Web unlock this key without asking. The passphrase travels inside your encrypted vault — but anyone with your vault passphrase could then read your encrypted mail.</p>
    </div>` : ''}
    <p class="muted small">Verify a contact's key by comparing the fingerprint with them by phone, in person, or another trusted channel.</p>`;
  if (!k.hasPrivate) {
    $('#kTrust').value = k.trust;
    $('#kTrust').onchange = async e => { await call('pgpSetTrust', k.fingerprint, e.target.value); loadKeys(); };
  }
  if (k.hasPrivate) wireSyncPassphrase(k); // 1.5.0
  const acts = $('#kActions');
  const btn = (label, fn, cls = '') => { const b = document.createElement('button'); b.className = 'btn small ' + cls; b.textContent = label; b.onclick = async () => { try { await fn(); } catch (e) { if (e.code !== 'CANCELLED') toast(e.message, 'err'); } }; acts.appendChild(b); };

  btn('Copy public key', async () => { await call('pgpCopyPublic', k.fingerprint); toast('Public key copied to clipboard'); });
  btn('Export public key…', async () => { const p = await call('pgpExportPublic', k.fingerprint); if (p) toast('Saved ' + p); });
  btn('Send public key by email', async () => {
    await call('pgpCopyPublic', k.fingerprint);
    await openComposer({});
    $('#cSubject').value = 'My OpenPGP public key';
    $('#cAttachKey').checked = true;
    $('#cBody').value = `Hi,\n\nAttached is my OpenPGP public key.\nFingerprint: ${k.fingerprintPretty}\n` + $('#cBody').value;
  });
  if (k.hasPrivate) {
    btn(k.unlocked ? 'Lock' : 'Unlock', async () => {
      if (k.unlocked) await call('pgpLockAll'); else await promptPassphrase(k.fingerprint, k.userIds[0]);
      loadKeys();
    });
    btn('Change passphrase…', () => changePassphrase(k));
    if (!k.revoked) btn('Extend expiry…', () => extendExpiryDialog(k)); // 1.1.0
    // 1.0.2: remember / forget the passphrase (Windows DPAPI)
    if (k.passphraseRemembered) {
      btn('Forget saved passphrase', async () => {
        await call('pgpForget', k.fingerprint);
        await call('pgpLockAll');
        toast('Saved passphrase removed. You will be asked again next time.');
        loadKeys();
      });
    } else {
      btn('Remember passphrase…', () => rememberPassphraseDialog(k));
    }
    btn('Publish to keys.openpgp.org', async () => {
      if (!(await confirmBox('Publish key', 'Upload your public key to keys.openpgp.org so others can find it by email? The server will email you a verification link.', 'Publish'))) return;
      const r = await call('pgpPublish', k.fingerprint);
      toast(r.verificationSentTo.length ? 'Uploaded. Check your inbox for the verification email.' : 'Uploaded.');
    });
    btn('Backup secret key…', async () => {
      if (!(await confirmBox('Export secret key', 'This file is your private key (still protected by your passphrase). Store it offline, e.g. on a USB drive. Anyone with this file AND your passphrase can read your mail.', 'Export'))) return;
      const p = await call('pgpExportPrivate', k.fingerprint); if (p) toast('Saved ' + p);
    });
    if (k.hasRevocationCert) btn('Export revocation certificate…', async () => { const p = await call('pgpExportRevocation', k.fingerprint); if (p) toast('Saved ' + p); });
    if (k.hasRevocationCert && !k.revoked) btn('Revoke key…', async () => {
      if (!(await confirmBox('Revoke key', 'Revoking is permanent. Use it if your key is lost or compromised, then share the updated public key so contacts stop using it.', 'Revoke key', true))) return;
      await call('pgpRevoke', k.fingerprint); toast('Key revoked. Re-publish or send your public key to contacts.'); loadKeys();
    }, 'danger');
  }
  btn('Delete…', async () => {
    const msg = k.hasPrivate
      ? 'This deletes your PRIVATE key. You will no longer be able to read messages encrypted to it unless you have a backup. Continue?'
      : 'Remove this public key from your keyring?';
    if (!(await confirmBox('Delete key', msg, 'Delete', true))) return;
    await call('pgpDelete', k.fingerprint, k.hasPrivate);
    state.selectedKey = null;
    toast('Key deleted');
    loadKeys();
    $('#keyDetail').innerHTML = '<div class="empty-state small"><p>Select a key to see details.</p></div>';
  }, 'danger');
}

// 1.5.0: "Remember passphrase on all my devices" (through the sync vault)
async function wireSyncPassphrase(k) {
  const box = $('#kSyncPass');
  let cloud = { connected: false };
  try { cloud = await call('cloudStatus'); } catch { /* ignore */ }
  if (!cloud.connected) {
    box.disabled = !k.passphraseSynced;
    $('#kSyncPassNote').textContent = 'Needs "Sync with my web server" (Settings). ' + $('#kSyncPassNote').textContent;
  }
  box.onchange = async () => {
    if (!box.checked) {
      try { await call('pgpUnsyncPassphrase', k.fingerprint); toast('Passphrase removed from your vault. Other devices will ask for it again.'); }
      catch (e) { box.checked = true; toast(e.message, 'err'); }
      return loadKeys();
    }
    box.checked = false;
    await dialog({
      title: 'Remember on all my devices',
      html: `<p>Sealpost will keep the passphrase for <b>${esc(k.userIds[0] || '')}</b> in your encrypted sync vault. Every Sealpost connected to your vault, and Sealpost Web, will then unlock this key automatically.</p>
        <p class="muted small">Your server can't read it. But from now on your <b>vault passphrase alone</b> is enough to read your encrypted mail — make sure it is long and used nowhere else. You can turn this off any time.</p>
        <label>Key passphrase</label><input type="password" id="spPass"><p id="spErr" class="error"></p>`,
      okText: 'Remember on all devices',
      onOk: async () => {
        $('#spErr').textContent = 'Checking…';
        const r = await window.api.pgpSyncPassphrase(k.fingerprint, $('#spPass').value);
        if (!r.ok) { $('#spErr').textContent = r.error; return false; }
        toast('Passphrase saved to your vault — your other devices will unlock this key automatically.');
        return true;
      }
    });
    loadKeys();
  };
}

// 1.0.2: save the passphrase so this key unlocks automatically
async function rememberPassphraseDialog(k) {
  await dialog({
    title: 'Remember passphrase',
    html: `<p>Sealpost will save the passphrase for <b>${esc(k.userIds[0] || '')}</b>, encrypted with your Windows login, and unlock this key automatically. Encrypted messages will open without a prompt.</p>
           <p class="muted small">Anyone who can sign in to your Windows account (or software running as you) could also read your encrypted mail. You can forget it any time here.</p>
           <label>Passphrase</label><input type="password" id="rmPass"><p id="rmErr" class="error"></p>`,
    okText: 'Remember',
    onOk: async () => {
      const r = await window.api.pgpRemember(k.fingerprint, $('#rmPass').value);
      if (!r.ok) { $('#rmErr').textContent = r.error; return false; }
      toast('Passphrase remembered — this key will unlock automatically.');
      loadKeys();
      return true;
    }
  });
}

/* ---------- 9b. Key expiry: warnings + extend (1.1.0) ---------- */
async function checkExpiry(announce) {
  let w = [];
  try { w = await call('pgpExpiryWarnings'); } catch { return; }
  show($('#keysDot'), w.length > 0);
  const box = $('#expiryBanner');
  box.innerHTML = '';
  for (const x of w) {
    const d = document.createElement('div');
    d.className = 'pgp-banner ' + (x.expired ? 'bad' : 'warn');
    d.innerHTML = `<span class="ico">⏳</span><div class="msg-txt"><b>${esc(x.userId)}</b> ${x.expired ? 'has <b>expired</b>' : `expires in <b>${x.daysLeft} day${x.daysLeft === 1 ? '' : 's'}</b>`} (${new Date(x.expires).toLocaleDateString()}).
      ${x.expired ? 'You can no longer sign, and people can no longer encrypt to you with it.' : 'After that you can no longer sign, and people can no longer encrypt to you.'} Extending keeps the same key.</div>`;
    const b = document.createElement('button');
    b.className = 'btn small primary'; b.textContent = 'Extend…';
    b.onclick = () => { const k = state.keys.find(y => y.fingerprint === x.fingerprint); if (k) extendExpiryDialog(k); };
    d.appendChild(b);
    box.appendChild(d);
  }
  if (announce && w.length) toast(`⏳ ${w[0].userId}: key ${w[0].expired ? 'has expired' : `expires in ${w[0].daysLeft} days`}. Keys → Extend expiry.`, 'warn');
}

async function extendExpiryDialog(k) {
  const r = await dialog({
    title: 'Extend key expiry',
    html: `<p>Give <b>${esc(k.userIds[0] || '')}</b> a new expiry date. The key and fingerprint stay the same — contacts just need your refreshed public key.</p>
      <p class="muted small">Current expiry: ${k.expires ? esc(new Date(k.expires).toLocaleDateString()) : 'never'}</p>
      <label>New expiry</label>
      <select id="exYears"><option value="1">1 year from today</option><option value="2" selected>2 years from today</option><option value="3">3 years from today</option><option value="5">5 years from today</option><option value="0">Never expires</option></select>
      <label>Key passphrase</label><input type="password" id="exPass"><p id="exErr" class="error"></p>`,
    okText: 'Extend',
    onOk: async () => {
      $('#dlgOk').disabled = true;
      const res = await window.api.pgpExtendExpiry(k.fingerprint, $('#exPass').value, Number($('#exYears').value));
      $('#dlgOk').disabled = false;
      if (!res.ok) { $('#exErr').textContent = res.error; return false; }
      return res.data;
    }
  });
  if (!r) return;
  await loadKeys();
  dialog({
    title: 'Expiry extended',
    html: `<p>New expiry: <b>${r.expires ? esc(new Date(r.expires).toLocaleDateString()) : 'never'}</b>.</p>
      <p>Your contacts still have the old expiry date. Share the refreshed public key:</p>
      <ul><li><b>Publish to keys.openpgp.org</b> (Keys view) so programs that look keys up get it automatically, and/or</li>
      <li>tick <b>Attach my public key</b> on your next message to each contact.</li></ul>`,
    hideCancel: true
  });
}

async function changePassphrase(k) {
  await dialog({
    title: 'Change passphrase',
    html: `<label>Current passphrase</label><input type="password" id="cp1">
           <label>New passphrase (min. 8)</label><input type="password" id="cp2">
           <label>Repeat new passphrase</label><input type="password" id="cp3"><p id="cpErr" class="error"></p>`,
    okText: 'Change',
    onOk: async () => {
      if ($('#cp2').value !== $('#cp3').value) { $('#cpErr').textContent = 'New passphrases do not match'; return false; }
      const r = await window.api.pgpChangePassphrase(k.fingerprint, $('#cp1').value, $('#cp2').value);
      if (!r.ok) { $('#cpErr').textContent = r.error; return false; }
      toast('Passphrase changed');
      return true;
    }
  });
}

/* ---------- Generate key ---------- */
function openGenerate(name = '', email = '') {
  const acct = state.accounts[0];
  $('#gName').value = name || acct?.name || '';
  $('#gEmail').value = email || acct?.email || '';
  $('#gPass').value = $('#gPass2').value = '';
  $('#gErr').textContent = '';
  openModal('#genModal');
}
$('#btnGenKey').addEventListener('click', () => openGenerate());
$('#gGo').addEventListener('click', async () => {
  if ($('#gPass').value !== $('#gPass2').value) { $('#gErr').textContent = 'Passphrases do not match'; return; }
  const b = $('#gGo');
  b.disabled = true; b.textContent = 'Generating…';
  try {
    const k = await call('pgpGenerate', { name: $('#gName').value.trim(), email: $('#gEmail').value.trim(), passphrase: $('#gPass').value, algorithm: $('#gAlgo').value, expireYears: $('#gExpire').value });
    closeModal('#genModal');
    toast('Key pair created: ' + k.fingerprintPretty);
    state.selectedKey = k.fingerprint;
    if ($('#view-keys').classList.contains('active')) loadKeys();
    if (!$('#composeModal').classList.contains('hidden')) updateKeyStatus();
    dialog({
      title: 'Your new key is ready',
      html: `<p>Fingerprint:</p><p class="fp">${esc(k.fingerprintPretty)}</p>
             <p>Next steps:</p><ol><li>Back up your secret key and revocation certificate (Keys → select key).</li>
             <li>Share your public key: publish it to keys.openpgp.org, or use "Attach my public key" when writing to contacts.</li></ol>`,
      hideCancel: true
    });
  } catch (e) {
    $('#gErr').textContent = e.message;
  } finally { b.disabled = false; b.textContent = 'Generate'; }
});

/* ---------- Import ---------- */
function importSummary(r) {
  const parts = [];
  if (r.imported.length) parts.push(`${r.imported.length} new public key(s)`);
  if (r.updated.length) parts.push(`${r.updated.length} updated`);
  if (r.secret.length) parts.push(`${r.secret.length} secret key(s)`);
  return parts.length ? 'Imported ' + parts.join(', ') : 'Nothing new to import';
}

$('#btnImportFile').addEventListener('click', async () => {
  try { const r = await call('pgpImportFile'); if (r) { toast(importSummary(r)); loadKeys(); } } catch (e) { toast(e.message, 'err'); }
});

$('#btnImportPaste').addEventListener('click', () => dialog({
  title: 'Paste a key',
  html: `<p class="muted">Paste an ASCII-armored public or (passphrase-protected) private key block.</p><textarea id="pasteKey" style="width:100%" placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----"></textarea><p id="pasteErr" class="error"></p>`,
  okText: 'Import',
  onOk: async () => {
    const r = await window.api.pgpImportText($('#pasteKey').value);
    if (!r.ok) { $('#pasteErr').textContent = r.error; return false; }
    toast(importSummary(r.data)); loadKeys(); return true;
  }
}));

/* ---------- Online lookup (WKD + keys.openpgp.org) ---------- */
$('#btnLookup').addEventListener('click', () => lookupDialog(''));

function lookupDialog(email, after) {
  dialog({
    title: 'Find a public key online',
    html: `<p class="muted">Searches the recipient's own domain (Web Key Directory) and keys.openpgp.org.</p>
      <div class="row gap"><input type="email" id="luEmail" placeholder="name@example.com" value="${esc(email)}"><button class="btn" id="luGo">Search</button></div>
      <div id="luRes"></div>`,
    okText: 'Close', hideCancel: true
  }).then(() => after && after());
  const go = async () => {
    const res = $('#luRes');
    res.innerHTML = '<p class="muted">Searching…</p>';
    try {
      const asked = $('#luEmail').value;
      const r = await call('pgpLookup', asked);
      res.innerHTML = '';
      // 1.13.0: an addy.io address is searched as the real recipient inside it
      if (r.via) res.innerHTML = `<p class="muted small">addy.io address — searching for the real recipient, <b>${esc(r.searched)}</b>.</p>`;
      if (!r.found.length) res.innerHTML += `<p>No key found.${r.errors.length ? '<br><span class="muted small">' + esc(r.errors.join(' · ')) + '</span>' : ''}</p><p class="muted small">Ask the person to send you their public key, or to publish it on keys.openpgp.org.</p>`;
      for (const f of r.found) {
        const el = document.createElement('div');
        el.className = 'lookup-result';
        el.innerHTML = `<b>${esc(f.info.userIds.join(', ') || '(email hidden by keyserver until verified)')}</b><div class="fp">${esc(f.info.fingerprintPretty)}</div>
          <div class="muted small">${esc(f.info.algorithm)} · created ${esc(new Date(f.info.created).toLocaleDateString())} · source: ${esc(f.source)}${f.info.revoked ? ' · REVOKED' : ''}${f.info.expired ? ' · EXPIRED' : ''}</div>`;
        const b = document.createElement('button');
        b.className = 'btn small primary'; b.textContent = 'Import'; b.style.marginTop = '6px';
        b.onclick = async () => {
          try {
            toast(importSummary(await call('pgpImportText', f.armored)));
            // 1.13.0: and to the contact for this address, if it has no key yet (as Sealpost Web does)
            const who = await call('contactsAssignFound', asked, f.info.fingerprint).catch(() => null);
            if (who) toast(`Key assigned to ${who}`);
            b.disabled = true; b.textContent = 'Imported';
            if ($('#view-keys').classList.contains('active')) loadKeys();
          } catch (e) { toast(e.message, 'err'); }
        };
        el.appendChild(b);
        res.appendChild(el);
      }
    } catch (e) { res.innerHTML = `<p class="error">${esc(e.message)}</p>`; }
  };
  $('#luGo').onclick = go;
  $('#luEmail').onkeydown = e => { if (e.key === 'Enter') go(); };
  if (email) go();
}

/* =================================================================
 * 9c. CONTACTS VIEW (1.1.0)
 *   A contact = name + addresses + an assigned PGP key + rules.
 *   The assigned key is always used when writing to that contact.
 * ================================================================= */
state.contacts = [];
state.selectedContact = null;

async function loadContacts() {
  try { state.contacts = await call('contactsList'); } catch (e) { toast(e.message, 'err'); state.contacts = []; }
  renderContactList();
  if (state.selectedContact === 'new') return;
  const c = state.contacts.find(x => x.id === state.selectedContact);
  if (c) renderContactDetail(c);
}

function renderContactList() {
  const q = $('#contactFilter').value.trim().toLowerCase();
  const list = $('#contactList');
  list.innerHTML = '';
  const items = state.contacts.filter(c => !q || (c.name || '').toLowerCase().includes(q) || c.emails.some(e => e.includes(q)));
  if (!items.length) list.innerHTML = `<div class="empty-state small"><p>${state.contacts.length ? 'No contacts match.' : 'No contacts yet. People you write to are added automatically, or click “New contact”.'}</p></div>`;
  for (const c of items) {
    const el = document.createElement('div');
    el.className = 'key-row' + (c.id === state.selectedContact ? ' active' : '');
    const k = c.key;
    const badges = [
      k ? (k.revoked ? '<span class="badge bad">KEY REVOKED</span>' : k.expired ? '<span class="badge bad">KEY EXPIRED</span>' : '<span class="badge enc">🔒 KEY</span>') : '<span class="badge plain">NO KEY</span>',
      k && (k.trust === 'verified') ? '<span class="badge sig">✔ VERIFIED</span>' : '',
      c.encrypt === 'always' ? '<span class="badge enc">ALWAYS ENCRYPT</span>' : ''
    ].join('');
    el.innerHTML = `<div class="uid">${esc(c.name || c.emails[0])}</div><div class="kid">${esc(c.emails.join(', '))}</div><div class="badges">${badges}</div>`;
    el.onclick = () => { state.selectedContact = c.id; renderContactList(); renderContactDetail(c); };
    list.appendChild(el);
  }
}
$('#contactFilter').addEventListener('input', renderContactList);
$('#btnNewContact').addEventListener('click', () => { state.selectedContact = 'new'; renderContactList(); renderContactDetail({ name: '', emails: [], encrypt: 'auto', sign: 'auto', notes: '' }); });

async function openContact(id) {
  switchView('contacts');
  state.selectedContact = id || null;
  await loadContacts();
}

async function renderContactDetail(c) {
  const d = $('#contactDetail');
  const isNew = !c.id;
  const k = c.key;
  d.innerHTML = `
    <h3 style="margin-top:0">${isNew ? 'New contact' : esc(c.name || c.emails[0])}</h3>
    <div class="contact-form">
      <label>Name</label><input id="ctName" type="text" value="${esc(c.name || '')}">
      <label>Email addresses</label><input id="ctEmails" type="text" value="${esc((c.emails || []).join(', '))}" placeholder="name@example.com, other@example.org">
      <label>Encryption</label>
      <select id="ctEncrypt"><option value="auto">Follow my default setting</option><option value="always">Always encrypt to this contact</option></select>
      <label>Signing</label>
      <select id="ctSign"><option value="auto">Follow my default setting</option><option value="always">Always sign</option><option value="never">Never sign (their mail program can't handle it)</option></select>
      <label>Notes</label><textarea id="ctNotes" rows="2">${esc(c.notes || '')}</textarea>
    </div>
    <h3>Assigned PGP key</h3>
    <div id="ctKeyArea"></div>
    <div class="key-actions" id="ctActions"></div>`;
  $('#ctEncrypt').value = c.encrypt || 'auto';
  $('#ctSign').value = c.sign || 'auto';

  const form = () => ({
    id: c.id, name: $('#ctName').value, emails: $('#ctEmails').value.split(/[,;\s]+/).filter(Boolean),
    encrypt: $('#ctEncrypt').value, sign: $('#ctSign').value, notes: $('#ctNotes').value
  });
  const save = async (quiet = false) => {
    const saved = await call('contactsSave', form());
    state.selectedContact = saved.id;
    if (!quiet) toast('Contact saved');
    await loadContacts();
    return saved;
  };

  /* --- key area --- */
  const area = $('#ctKeyArea');
  if (isNew) area.innerHTML = '<p class="muted small">Save the contact first. A key already in your keyring for these addresses is assigned automatically.</p>';
  else {
    if (k) {
      area.innerHTML = `<div class="key-box">
        <div><b>${esc(k.userIds[0] || '')}</b></div>
        <div class="fp">${esc(k.fingerprintPretty)}</div>
        <div class="muted small">${esc(k.algorithm)} · created ${esc(new Date(k.created).toLocaleDateString())} · ${k.expires ? (k.expired ? '<b style="color:var(--red)">expired</b> ' : 'expires ') + esc(new Date(k.expires).toLocaleDateString()) : 'no expiry'}${k.revoked ? ' · <b style="color:var(--red)">REVOKED</b>' : ''}</div>
        <div class="small" style="margin-top:4px">${k.trust === 'verified' ? '✔ <b>Verified</b> — you confirmed this fingerprint with them' : 'Not verified yet — compare the fingerprint with them by phone or in person, then mark it verified.'}</div>
      </div>`;
    } else area.innerHTML = '<p class="muted">No key assigned — messages to this contact can\'t be encrypted.</p>';

    // other keys in the keyring for these addresses
    let cands = [];
    try { cands = await call('contactsCandidateKeys', c.id); } catch { /* ignore */ }
    const others = cands.filter(x => !k || x.fingerprint !== k.fingerprint);
    if (others.length) {
      const w = document.createElement('div');
      w.className = 'inline-warn small';
      w.innerHTML = `<b>${k ? '⚠ Other keys exist for this address' : 'Keys found for this address'}</b>${k ? ' — Sealpost keeps using the assigned key. If they really changed keys, confirm with them, then switch.' : ''}<br>`;
      for (const o of others) {
        const row = document.createElement('div');
        row.style.margin = '6px 0';
        row.innerHTML = `<span class="fp">${esc(o.fingerprintPretty)}</span> <span class="muted">· created ${esc(new Date(o.created).toLocaleDateString())}${o.expired ? ' · expired' : ''}${o.revoked ? ' · revoked' : ''}</span> `;
        const b = document.createElement('button');
        b.className = 'btn small'; b.textContent = k ? 'Switch to this key' : 'Assign';
        b.onclick = async () => {
          if (k && !(await confirmBox('Switch key', 'Use this key for the contact from now on? Only do this after confirming the change with them.', 'Switch', true))) return;
          await call('contactsPinKey', c.id, o.fingerprint); toast('Key assigned'); loadContacts();
        };
        row.appendChild(b);
        w.appendChild(row);
      }
      area.appendChild(w);
    }
  }

  /* --- actions --- */
  const acts = $('#ctActions');
  const btn = (label, fn, cls = '') => { const b = document.createElement('button'); b.className = 'btn small ' + cls; b.textContent = label; b.onclick = async () => { try { await fn(); } catch (e) { if (e.code !== 'CANCELLED') toast(e.message, 'err'); } }; acts.appendChild(b); };
  btn(isNew ? 'Create contact' : 'Save changes', () => save(), 'primary');
  if (!isNew) {
    btn('✉ Write email', () => openComposer({ to: c.name ? `${c.name} <${c.emails[0]}>` : c.emails[0] }));
    if (k) btn(k.trust === 'verified' ? 'Mark as not verified' : '✔ Mark key verified', async () => {
      await call('pgpSetTrust', k.fingerprint, k.trust === 'verified' ? 'unknown' : 'verified'); loadContacts();
    });
    btn('Paste key…', () => dialog({
      title: 'Assign a key to ' + (c.name || c.emails[0]),
      html: '<p class="muted">Paste their ASCII-armored public key.</p><textarea id="ctPaste" style="width:100%" placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----"></textarea><p id="ctPasteErr" class="error"></p>',
      okText: 'Assign key',
      onOk: async () => {
        const r = await window.api.contactsImportKeyFor(c.id, $('#ctPaste').value);
        if (!r.ok) { $('#ctPasteErr').textContent = r.error; return false; }
        toast('Key assigned'); loadContacts(); return true;
      }
    }));
    btn('Find key online…', () => lookupDialog(c.emails[0], () => loadContacts()));
    if (k) btn('Remove key from contact', async () => { await call('contactsPinKey', c.id, null); loadContacts(); });
    btn('Delete contact', async () => {
      if (!(await confirmBox('Delete contact', `Delete ${c.name || c.emails[0]}? Their key stays in your keyring.`, 'Delete', true))) return;
      await call('contactsDelete', c.id);
      state.selectedContact = null;
      $('#contactDetail').innerHTML = '<div class="empty-state small"><p>Select a contact, or create one.</p></div>';
      loadContacts();
    }, 'danger');
  }
}

/* =================================================================
 * 10. PGP TOOLS
 * ================================================================= */
async function loadToolSigners() {
  const keys = await call('pgpList');
  const sel = $('#toolSigner');
  const cur = sel.value;
  sel.innerHTML = '<option value="">(don\'t sign)</option>';
  for (const k of keys.filter(k => k.hasPrivate && !k.revoked)) {
    for (const e of k.emails) {
      const o = document.createElement('option');
      o.value = e; o.textContent = `${k.userIds[0]}`;
      sel.appendChild(o);
    }
  }
  sel.value = cur;
}

function toolStatus(html, kind = 'ok') { $('#toolStatus').innerHTML = html ? `<div class="pgp-banner ${kind}"><div class="msg-txt">${html}</div></div>` : ''; }

function sigSummary(sigs) {
  if (!sigs || !sigs.length) return 'No signature.';
  return sigs.map(s => s.valid ? `✔ Good signature from ${esc(s.signer)}` : s.unknownKey ? `? Signed by unknown key ${esc(s.keyId)}` : `✖ BAD signature (${esc(s.signer || s.keyId)})`).join('<br>');
}

$('#toolPaste').addEventListener('click', async () => { $('#toolIn').value = await call('clipboardRead'); });
$('#toolClear').addEventListener('click', () => { $('#toolIn').value = ''; $('#toolOut').value = ''; toolStatus(''); });
$('#toolCopy').addEventListener('click', async () => { await call('clipboardWrite', $('#toolOut').value); toast('Copied'); });

$('#toolEncrypt').addEventListener('click', async () => {
  try {
    const recipients = $('#toolRecipients').value.split(/[,;\s]+/).filter(Boolean);
    if (!recipients.length) return toast('Enter at least one recipient email', 'warn');
    $('#toolOut').value = await call('toolsEncrypt', { text: $('#toolIn').value, recipients, signWith: $('#toolSigner').value || null });
    toolStatus('🔒 Encrypted' + ($('#toolSigner').value ? ' and signed' : '') + '. Copy the output and paste it anywhere.');
  } catch (e) { if (e.code !== 'CANCELLED') toolStatus(esc(e.message), 'bad'); }
});

$('#toolSign').addEventListener('click', async () => {
  try {
    if (!$('#toolSigner').value) return toast('Choose a key under "Sign with"', 'warn');
    $('#toolOut').value = await call('toolsSign', { text: $('#toolIn').value, signWith: $('#toolSigner').value });
    toolStatus('✍ Signed (cleartext). Anyone can read it; PGP users can verify it.');
  } catch (e) { if (e.code !== 'CANCELLED') toolStatus(esc(e.message), 'bad'); }
});

$('#toolProcess').addEventListener('click', async () => {
  try {
    const r = await call('toolsProcess', $('#toolIn').value);
    if (r.kind === 'imported') { $('#toolOut').value = ''; toolStatus(esc(importSummary(r.result))); return; }
    $('#toolOut').value = r.text;
    const bad = r.signatures.some(s => !s.valid && !s.unknownKey);
    toolStatus((r.kind === 'decrypted' ? '🔓 Decrypted.<br>' : '') + sigSummary(r.signatures), bad ? 'bad' : 'ok');
  } catch (e) { if (e.code !== 'CANCELLED') toolStatus(esc(e.message), 'bad'); }
});

/* =================================================================
 * 11. SETTINGS + ACCOUNT EDITOR
 * ================================================================= */
async function loadSettingsView() {
  const s = state.settings = await call('settingsGet');
  $('#setRemote').checked = s.loadRemoteImages;
  $('#setCache').value = s.passphraseCacheMinutes;
  $('#setSign').checked = s.defaultSign;
  $('#setEncrypt').checked = s.defaultEncrypt;
  $('#setAttachKey').checked = s.attachPublicKey;
  $('#setPage').value = s.pageSize;
  $('#setFormat').value = s.composeFormat === 'rich' ? 'rich' : 'plain';     // 1.1.0
  $('#setAutoContacts').checked = s.autoAddContacts !== false;               // 1.1.0
  $('#setPush').checked = s.pushMail !== false;                              // 1.2.0
  $('#setNotify').checked = s.notifyNewMail !== false;                       // 1.2.0
  $('#setAddy').checked = !!s.addyRecipients;                                // 1.13.0
  $('#setAddyDomains').value = (s.addyDomains || []).join(', ');             // 1.13.0
  renderStartChoice();                                                       // 1.13.2
  renderLastBackup();                                                        // 1.2.0
  renderOfflinePanel();                                                      // 1.3.0
  renderCloudPanel();                                                        // 1.4.0
  renderLockPanel();                                                         // 1.1.0
  renderAccountList();
  try { $('#appVersion').textContent = (await call('appInfo')).version; } catch { /* ignore */ }
}

/* ---------- Install a .sealpost update file (added 1.0.1) ---------- */
$('#btnInstallUpdate').addEventListener('click', async () => {
  try {
    const r = await call('appInstallUpdate');
    if (!r) return; // cancelled
    const ok = await confirmBox('Update ready', `Version ${r.version} is installed (you had ${r.from}). Restart Sealpost now to use it?`, 'Restart now');
    if (ok) await call('appRestart');
    else toast(`Update to ${r.version} will apply next time Sealpost starts.`);
  } catch (e) { toast(e.message, 'err'); }
});

/* ---------- Check for updates on GitHub (added 1.12.0) ---------- */
$('#btnCheckUpdate').addEventListener('click', async () => {
  const btn = $('#btnCheckUpdate'), status = $('#updateStatus');
  btn.disabled = true; status.textContent = 'Checking GitHub for updates…';
  try {
    const u = await call('appCheckUpdate');
    if (!u.latest) { status.textContent = 'No Sealpost releases were found on GitHub.'; return; }
    if (!u.newer) { status.textContent = `You have the newest version (${u.current}).`; return; }
    status.textContent = `Version ${u.latest} is available (you have ${u.current}).`;
    if (!u.file) {
      if (await confirmBox('Update available', `Sealpost ${u.latest} is available, but it has no update file. Open the release page to download the installer?`, 'Open release page')) call('shellOpenExternal', u.page);
      return;
    }
    const sizeMB = u.file.size ? ` (${(u.file.size / 1048576).toFixed(1)} MB)` : '';
    if (!(await confirmBox('Update available', `Sealpost ${u.latest} is available (you have ${u.current}). Download and install it from GitHub now${sizeMB}?`, 'Download and install'))) return;
    status.textContent = `Downloading Sealpost ${u.latest}…`;
    const r = await call('appDownloadUpdate');
    status.textContent = `Version ${r.version} is installed.`;
    const ok = await confirmBox('Update ready', `Version ${r.version} is installed (you had ${r.from}). Restart Sealpost now to use it?`, 'Restart now');
    if (ok) await call('appRestart');
    else toast(`Update to ${r.version} will apply next time Sealpost starts.`);
  } catch (e) { status.textContent = ''; toast(e.message, 'err'); }
  finally { btn.disabled = false; }
});
$('#btnReleasesPage').addEventListener('click', () => call('appReleasesPage').catch(e => toast(e.message, 'err')));

$('#btnSaveSettings').addEventListener('click', async () => {
  state.settings = await call('settingsSet', {
    loadRemoteImages: $('#setRemote').checked,
    passphraseCacheMinutes: Number($('#setCache').value) || 0,
    defaultSign: $('#setSign').checked,
    defaultEncrypt: $('#setEncrypt').checked,
    attachPublicKey: $('#setAttachKey').checked,
    pageSize: Math.min(500, Math.max(10, Number($('#setPage').value) || 50)),
    composeFormat: $('#setFormat').value,
    autoAddContacts: $('#setAutoContacts').checked,
    pushMail: $('#setPush').checked,
    notifyNewMail: $('#setNotify').checked,
    addyRecipients: $('#setAddy').checked,       // 1.13.0
    addyDomains: $('#setAddyDomains').value,
    startFolder: $('#setStart').value ? JSON.parse($('#setStart').value) : null   // 1.13.2
  });
  renderPushStatus();
  toast('Settings saved');
});

/* 1.13.2: Settings -> "When Sealpost starts, open": All Inboxes or any folder */
function renderStartChoice() {
  const sel = $('#setStart'), sf = startPref();
  const opt = (v, label) => `<option value="${esc(v ? JSON.stringify(v) : '')}">${esc(label)}</option>`;
  let html = opt(null, 'The first account\'s Inbox');
  if (state.accounts.length > 1) html += opt({ accId: UNIFIED, path: 'INBOX' }, 'All Inboxes');
  for (const a of state.accounts) {
    const folders = (state.folders[a.id] || []).filter(f => !f.noselect);
    if (sf && sf.accId === a.id && !folders.some(f => f.path === sf.path)) folders.push({ path: sf.path, depth: 0 });   // not loaded yet
    html += `<optgroup label="${esc(a.email)}">${folders.map(f => opt({ accId: a.id, path: f.path }, '\u00a0'.repeat((f.depth || 0) * 3) + (f.path.toUpperCase() === 'INBOX' ? 'Inbox' : f.name || f.path))).join('')}</optgroup>`;
  }
  sel.innerHTML = html;
  sel.value = sf ? JSON.stringify({ accId: sf.accId, path: sf.path }) : '';
  if (sel.selectedIndex < 0) sel.value = '';
}

function renderAccountList() {
  const box = $('#accountList');
  box.innerHTML = state.accounts.length ? '' : '<p class="muted">No accounts yet.</p>';
  state.accounts.forEach((a, i) => {
    const el = document.createElement('div');
    el.className = 'acct';
    el.innerHTML = `<div class="info"><div><b>${esc(a.name || a.email)}</b></div><div class="muted small">${esc(a.email)} · ${esc(a.imapHost)}</div>${(a.aliases || []).length ? `<div class="muted small">Also sends as ${esc(a.aliases.map(x => x.email).join(', '))}</div>` : ''}</div>`;
    // 1.13.2: arrange the accounts (the sidebar and every account list follow this order)
    if (state.accounts.length > 1) {
      const ord = document.createElement('div'); ord.className = 'acct-order';
      for (const [d, t, tip] of [[-1, '▲', 'Move up'], [1, '▼', 'Move down']]) {
        const b = document.createElement('button'); b.className = 'btn small'; b.textContent = t; b.title = tip;
        b.disabled = i + d < 0 || i + d >= state.accounts.length;
        b.onclick = () => moveAccount(a.id, d);
        ord.appendChild(b);
      }
      el.appendChild(ord);
    }
    const e = document.createElement('button'); e.className = 'btn small'; e.textContent = 'Edit'; e.onclick = () => openAccountEditor(a);
    const d = document.createElement('button'); d.className = 'btn small danger'; d.textContent = 'Remove';
    d.onclick = async () => {
      if (!(await confirmBox('Remove account', `Remove ${a.email} from Sealpost? Mail on the server is not affected.`, 'Remove', true))) return;
      await call('accountsDelete', a.id);
      if (state.cur.accId === a.id) state.cur.accId = null;
      await loadAccounts(); renderAccountList();
    };
    el.append(e, d);
    box.appendChild(el);
  });
}

let presets = [];
let editingAccount = null;

async function openAccountEditor(acc = null) {
  if (!presets.length) presets = await call('accountsPresets');
  editingAccount = acc;
  $('#acctTitle').textContent = acc ? 'Edit account' : 'Add account';
  show($('#aRestoreHint'), !acc && !state.accounts.length); // 1.2.0
  const sel = $('#aPreset');
  sel.innerHTML = presets.map(p => `<option value="${esc(p.id)}">${esc(p.label)}</option>`).join('');
  const set = (id, v) => { $(id).value = v ?? ''; };
  if (acc) {
    sel.value = 'custom';
    set('#aName', acc.name); set('#aEmail', acc.email); set('#aUser', acc.username);
    set('#aImapHost', acc.imapHost); set('#aImapPort', acc.imapPort); set('#aImapSec', acc.imapSecurity);
    set('#aSmtpHost', acc.smtpHost); set('#aSmtpPort', acc.smtpPort); set('#aSmtpSec', acc.smtpSecurity);
    set('#aSmtpUser', acc.smtpUsername); set('#aSig', acc.signature);
    set('#aAliases', (acc.aliases || []).map(x => x.name ? `${x.name} <${x.email}>` : x.email).join('\n'));   // 1.9.0
    $('#aSelfSigned').checked = !!acc.allowSelfSigned;
    $('#aConv').checked = !!acc.conversationView;   // 1.10.0
    $('#aPass').placeholder = '(unchanged)';
  } else {
    ['#aName', '#aEmail', '#aUser', '#aSmtpUser', '#aSig', '#aAliases'].forEach(i => set(i, ''));
    $('#aConv').checked = false;
    $('#aPass').placeholder = '';
    sel.value = 'gmail';
    applyPreset();
  }
  set('#aPass', ''); set('#aSmtpPass', '');
  $('#aNote').textContent = acc ? '' : $('#aNote').textContent;
  $('#aResult').textContent = '';
  openModal('#acctModal');
}

function applyPreset() {
  const p = presets.find(x => x.id === $('#aPreset').value);
  if (!p) return;
  $('#aImapHost').value = p.imapHost; $('#aImapPort').value = p.imapPort; $('#aImapSec').value = p.imapSecurity;
  $('#aSmtpHost').value = p.smtpHost; $('#aSmtpPort').value = p.smtpPort; $('#aSmtpSec').value = p.smtpSecurity;
  $('#aSelfSigned').checked = !!p.allowSelfSigned;
  $('#aNote').textContent = p.note || '';
}
$('#aPreset').addEventListener('change', applyPreset);
$('#aEmail').addEventListener('input', e => { if (!editingAccount) $('#aUser').value = e.target.value; });

function accountForm() {
  return {
    id: editingAccount?.id,
    name: $('#aName').value.trim(), email: $('#aEmail').value.trim(), username: $('#aUser').value.trim(),
    password: $('#aPass').value,
    imapHost: $('#aImapHost').value.trim(), imapPort: $('#aImapPort').value, imapSecurity: $('#aImapSec').value,
    smtpHost: $('#aSmtpHost').value.trim(), smtpPort: $('#aSmtpPort').value, smtpSecurity: $('#aSmtpSec').value,
    smtpUsername: $('#aSmtpUser').value.trim(), smtpPassword: $('#aSmtpPass').value,
    allowSelfSigned: $('#aSelfSigned').checked, signature: $('#aSig').value,
    aliases: parseAliases($('#aAliases').value),   // 1.9.0
    conversationView: $('#aConv').checked          // 1.10.0
  };
}

/* 1.9.0: "Name <email>" or "email" per line -> [{ name, email, signature }] */
function parseAliases(text) {
  const old = new Map(((editingAccount && editingAccount.aliases) || []).map(a => [a.email.toLowerCase(), a]));
  return String(text || '').split(/\r?\n/).map(l => l.trim()).filter(Boolean).map(l => {
    const m = l.match(/^(.*?)\s*<([^>]+)>\s*$/);
    const email = (m ? m[2] : l).trim(), name = (m ? m[1] : '').replace(/^"|"$/g, '').trim();
    const prev = old.get(email.toLowerCase());
    return { email, name, signature: prev ? prev.signature || '' : '' };
  });
}

$('#aTest').addEventListener('click', async () => {
  $('#aResult').textContent = 'Testing…';
  try {
    const r = await call('accountsTest', accountForm());
    $('#aResult').innerHTML = `IMAP: <b>${esc(r.imap)}</b> &nbsp; SMTP: <b>${esc(r.smtp)}</b>`;
  } catch (e) { $('#aResult').textContent = e.message; }
});

$('#aSave').addEventListener('click', async () => {
  const f = accountForm();
  if (!f.email || !f.imapHost || !f.smtpHost) { $('#aResult').textContent = 'Email, IMAP server and SMTP server are required.'; return; }
  if (!f.id && !f.password) { $('#aResult').textContent = 'Enter the password (or app password).'; return; }
  const badAlias = f.aliases.find(a => !/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(a.email));
  if (badAlias) { $('#aResult').textContent = `"${badAlias.email}" in "Send as" isn't an email address.`; return; }
  try {
    const saved = await call('accountsSave', f);
    closeModal('#acctModal');
    toast('Account saved');
    state.cur.accId = saved.id; state.cur.folder = 'INBOX';
    await loadAccounts();
    renderAccountList();
    // first account and no key yet? offer to make one
    const mine = await call('pgpSecretFor', saved.email);
    if (!mine && await confirmBox('Set up encryption', `You don't have a PGP key for ${saved.email} yet. Create one now?`, 'Create key')) {
      openGenerate(saved.name, saved.email);
    }
  } catch (e) { $('#aResult').textContent = e.message; }
});
$('#btnAddAccount').addEventListener('click', () => openAccountEditor());
$('#aRestoreBtn').addEventListener('click', () => { closeModal('#acctModal'); switchView('settings'); $('#btnRestore').click(); }); // 1.2.0


/* =================================================================
 * 11c. BACKUP & RESTORE (1.2.0)
 * ================================================================= */
function renderLastBackup() {
  const lb = state.settings.lastBackup;
  const el = $('#lastBackup');
  if (!lb) { el.innerHTML = '⚠ <b>No backup yet.</b> If this PC\'s drive fails, a backup is the only way to get your PGP keys back.'; return; }
  const days = Math.floor((Date.now() - new Date(lb)) / 86400000);
  el.innerHTML = `Last backup: <b>${esc(new Date(lb).toLocaleString())}</b>${days > 90 ? ' — <span style="color:var(--amber)">over 3 months ago; consider a fresh one</span>' : ''}`;
}

$('#btnBackup').addEventListener('click', () => dialog({
  title: 'Create backup',
  html: `<p>Choose a passphrase for the backup file. You'll need it to restore — it <b>cannot be recovered</b>.</p>
    <label>Backup passphrase (at least 10 characters)</label><input type="password" id="bkP1" autocomplete="new-password">
    <label>Repeat passphrase</label><input type="password" id="bkP2" autocomplete="new-password">
    <p class="muted small">Included: accounts and their passwords, settings, contacts, all public keys, your secret keys (still protected by their own passphrases) and revocation certificates.
    Not included: "Remember passphrase" (tick it again on the new PC) and your messages (they stay on the mail server).</p>
    <p id="bkErr" class="error"></p>`,
  okText: 'Create backup',
  onOk: async () => {
    if ($('#bkP1').value !== $('#bkP2').value) { $('#bkErr').textContent = 'Passphrases do not match'; return false; }
    if ($('#bkP1').value.length < 10) { $('#bkErr').textContent = 'Use at least 10 characters'; return false; }
    $('#bkErr').textContent = 'Encrypting…'; $('#dlgOk').disabled = true;
    const r = await window.api.backupCreate($('#bkP1').value);
    $('#dlgOk').disabled = false;
    if (!r.ok) { $('#bkErr').textContent = r.error; return false; }
    if (!r.data) { $('#bkErr').textContent = ''; return false; } // save dialog cancelled
    state.settings = await call('settingsGet');
    renderLastBackup();
    const s = r.data.summary;
    toast(`Backup saved and checked: ${s.accounts.length} account(s), ${s.secretKeys} secret key(s), ${s.publicKeys} key(s), ${s.contacts} contact(s).`);
    return true;
  }
}));

$('#btnRestore').addEventListener('click', async () => {
  const picked = await call('backupPick');
  if (!picked) return;
  const summary = await dialog({
    title: 'Restore from backup',
    html: `<p>File: <b>${esc(picked.name)}</b></p><label>Backup passphrase</label><input type="password" id="rsPass"><p id="rsErr" class="error"></p>`,
    okText: 'Open backup',
    onOk: async () => {
      $('#rsErr').textContent = 'Decrypting…'; $('#dlgOk').disabled = true;
      const r = await window.api.backupRead($('#rsPass').value);
      $('#dlgOk').disabled = false;
      if (!r.ok) { $('#rsErr').textContent = r.error; return false; }
      return r.data;
    }
  });
  if (!summary) return;
  const fresh = !state.accounts.length;
  const go = await dialog({
    title: 'Restore from backup',
    html: `<div class="restore-summary">Backup from <b>${esc(new Date(summary.created).toLocaleString())}</b> (Sealpost ${esc(summary.appVersion || '?')})
      <ul>
        <li>${summary.accounts.length} account(s): ${esc(summary.accounts.join(', ') || '—')}</li>
        <li>${summary.secretKeys} secret key(s), ${summary.publicKeys} key(s) in total</li>
        <li>${summary.contacts} contact(s)</li>
        ${summary.appLock ? '<li>App lock with its PIN</li>' : ''}
      </ul></div>
      <p class="small">Restoring <b>adds</b> what's missing on this PC. Nothing here is deleted; accounts and contacts you already have are kept as they are.</p>
      <label class="check"><input type="checkbox" id="rsSettings" ${fresh ? 'checked' : ''}> Also restore settings${summary.appLock ? ' (including the app lock PIN)' : ''}</label>`,
    okText: 'Restore'
  });
  if (!go) return;
  try {
    const res = await call('backupRestore', { restoreSettings: $('#rsSettings') ? $('#rsSettings').checked : fresh });
    await dialog({
      title: 'Restore complete',
      html: `<ul>
        <li>Accounts added: ${res.accountsAdded.length ? esc(res.accountsAdded.join(', ')) : 'none'}${res.accountsSkipped.length ? ` (already here: ${esc(res.accountsSkipped.join(', '))})` : ''}</li>
        <li>Secret keys: ${res.secretKeys}; new public keys: ${res.keysImported}${res.keysUpdated ? `, updated: ${res.keysUpdated}` : ''}</li>
        <li>Contacts added: ${res.contactsAdded}${res.contactsSkipped ? ` (${res.contactsSkipped} already here)` : ''}</li>
        <li>Settings ${res.settings ? 'restored' : 'kept as they were'}</li>
      </ul>
      ${res.errors.length ? `<p class="error">${res.errors.map(esc).join('<br>')}</p>` : ''}
      <p class="muted small">If you used "Remember passphrase" before, tick it again the next time you unlock your key.</p>`,
      hideCancel: true, okText: 'Reload Sealpost'
    });
    call('appReload'); // main process reloads the window (in-page reload is blocked by design)
  } catch (e) { toast('Restore failed: ' + e.message, 'err'); }
});

/* =================================================================
 * 11d. SYNC WITH MY WEB SERVER (1.4.0)
 *    Panel in Settings, the set-up wizard, devices, passphrase change,
 *    and reacting when another PC changed something.
 * ================================================================= */
let cloudNagShown = false;

const fmtWhen = iso => iso ? new Date(iso).toLocaleString() : 'not yet';

/* ---------- Settings panel ---------- */
async function renderCloudPanel() {
  const body = $('#cloudPanelBody');
  let s;
  try { s = await call('cloudStatus'); } catch { return; }
  if (!s.connected) {
    body.innerHTML = `<p class="small">Not set up on this PC.</p>
      <div class="row gap wrap"><button id="cloudSetup" class="btn primary">Set up sync…</button></div>`;
    $('#cloudSetup').onclick = () => cloudWizard();
    return;
  }
  const dot = s.needs ? 'bad' : s.lastError ? 'warn' : '';
  const stateLine = s.running ? 'Syncing…'
    : s.needs === 'passphrase' ? 'Paused — the vault passphrase was changed on another device'
    : s.needs === 'signin' ? 'Paused — this PC was signed out of the vault'
    : s.lastError ? 'Last attempt failed: ' + esc(s.lastError)
    : 'Up to date';
  body.innerHTML = `<div class="cloud-status small">
      <div><span class="dot ${dot}"></span><b>${stateLine}</b></div>
      <div>Server: <b>${esc(s.server)}</b></div>
      <div>Vault user: <b>${esc(s.username)}</b> · this PC: <b>${esc(s.deviceName)}</b></div>
      <div>Last sync: ${esc(fmtWhen(s.lastSync))} · ${s.items} item(s) in sync</div>
    </div>
    <div class="row gap wrap">
      ${s.needs ? `<button id="cloudReauth" class="btn primary">Enter vault passphrase…</button>` : `<button id="cloudNow" class="btn primary" ${s.running ? 'disabled' : ''}>Sync now</button>`}
      <button id="cloudDevices" class="btn">Devices…</button>
      <button id="cloudPass" class="btn">Change vault passphrase…</button>
      <button id="cloudOff" class="btn ghost">Stop syncing on this PC…</button>
    </div>`;
  if ($('#cloudNow')) $('#cloudNow').onclick = cloudSyncNow;
  if ($('#cloudReauth')) $('#cloudReauth').onclick = () => cloudReauth(s.needs);
  $('#cloudDevices').onclick = cloudDevicesDialog;
  $('#cloudPass').onclick = cloudChangePassphrase;
  $('#cloudOff').onclick = cloudDisconnect;
}

async function cloudSyncNow() {
  $('#cloudNow').disabled = true;
  try {
    const r = await call('cloudSyncNow');
    if (r.result && r.result.error) { if (!r.needs) toast('Sync failed: ' + r.result.error, 'err'); }
    else if (r.result) toast(`Synced — ${r.result.pushed} sent, ${r.result.applied} received.`);
  } catch (e) { toast(e.message, 'err'); }
  renderCloudPanel();
}

/* ---------- Set-up wizard: 1) address  2) create or connect ---------- */
async function cloudWizard() {
  const probe = await dialog({
    title: 'Set up sync — your server',
    html: `<p>Enter the address of the folder where you uploaded the Sealpost Sync files. It's shown on that folder's start page, e.g. <span class="cloud-code">https://example.com/sealpost/</span></p>
      <label>Server address</label><input type="text" id="cwServer" placeholder="https://your-site/…/" spellcheck="false">
      <p id="cwErr" class="error"></p>`,
    okText: 'Next',
    onOk: async () => {
      $('#cwErr').textContent = 'Checking…'; $('#dlgOk').disabled = true;
      const r = await window.api.cloudProbe($('#cwServer').value);
      $('#dlgOk').disabled = false;
      if (!r.ok) { $('#cwErr').textContent = r.error; return false; }
      return r.data;
    }
  });
  if (!probe) return;

  const create = !probe.vault;
  if (create && !probe.setupOpen) { await dialog({ title: 'Set up sync', html: '<p>This server has no vault yet, and creating one is switched off in its config.php.</p>', hideCancel: true }); return; }

  const html = create
    ? `<p>No vault on <b>${esc(probe.server)}</b> yet — create it now. Everything on this PC (accounts, contacts, keys, settings) is uploaded, encrypted.</p>
       <label>Vault username</label><input type="text" id="cwUser" placeholder="e.g. jeff" spellcheck="false">
       <label>Vault passphrase (at least 10 characters)</label><input type="password" id="cwP1" autocomplete="new-password">
       <label>Repeat passphrase</label><input type="password" id="cwP2" autocomplete="new-password">
       <label>Setup code (from config.php on your server)</label><input type="text" id="cwCode" class="cloud-code" placeholder="XXXX-XXXX-XXXX-XXXX" spellcheck="false">
       <label>Name for this PC (optional)</label><input type="text" id="cwDev" placeholder="e.g. Office PC">
       <p class="muted small">The passphrase never leaves this PC and <b>cannot be recovered</b> — your server only ever sees encrypted data. Use something long you won't forget (a few unrelated words works well).</p>
       <p id="cwErr" class="error"></p>`
    : `<p>Connect this PC to the vault on <b>${esc(probe.server)}</b>. What's in the vault is added here; anything only on this PC is added to the vault. Where both have the same item, the vault's copy is used.</p>
       <label>Vault username</label><input type="text" id="cwUser" spellcheck="false">
       <label>Vault passphrase</label><input type="password" id="cwP1" autocomplete="current-password">
       <label>Name for this PC (optional)</label><input type="text" id="cwDev" placeholder="e.g. Laptop">
       <p id="cwErr" class="error"></p>`;

  const res = await dialog({
    title: create ? 'Set up sync — create your vault' : 'Set up sync — connect',
    html,
    okText: create ? 'Create vault' : 'Connect',
    onOk: async () => {
      const p1 = $('#cwP1').value;
      if (create) {
        if (p1.length < 10) { $('#cwErr').textContent = 'Use at least 10 characters'; return false; }
        if (p1 !== $('#cwP2').value) { $('#cwErr').textContent = 'Passphrases do not match'; return false; }
      }
      $('#cwErr').textContent = create ? 'Creating the vault and uploading — this takes a few seconds…' : 'Connecting and syncing — this takes a few seconds…';
      $('#dlgOk').disabled = true;
      const r = await window.api.cloudConnect({
        server: probe.server, username: $('#cwUser').value, passphrase: p1, create,
        setupCode: create ? $('#cwCode').value : '', deviceName: $('#cwDev').value.trim()
      });
      $('#dlgOk').disabled = false;
      if (!r.ok) { $('#cwErr').textContent = r.error; return false; }
      return r.data;
    }
  });
  if (!res) return;
  const rr = res.result || {};
  await dialog({
    title: 'Sync is on',
    html: rr.error
      ? `<p>Connected, but the first sync had a problem: <span class="error">${esc(rr.error)}</span></p><p class="small">Sealpost keeps trying in the background.</p>`
      : `<p>${create ? 'Your vault is created.' : 'This PC is connected to your vault.'} ${rr.pushed} item(s) sent, ${rr.applied} received.</p>
         <p class="small">From now on changes sync automatically a few seconds after you make them, and every 5 minutes.${create ? ' On your other PCs choose <b>Settings → Sync with my web server → Set up sync</b> and use the same address, username and passphrase.' : ''}</p>`,
    hideCancel: true, okText: rr.applied ? 'Reload Sealpost' : 'OK'
  });
  if (rr.applied) call('appReload');
  else renderCloudPanel();
}

/* ---------- Passphrase after a change elsewhere / sign in again ---------- */
async function cloudReauth(needs) {
  const r = await dialog({
    title: needs === 'signin' ? 'Sign this PC in again' : 'New vault passphrase',
    html: `<p>${needs === 'signin' ? 'This PC was signed out of your vault (from another device). Enter the vault passphrase to sign in again.' : 'The vault passphrase was changed on another device. Enter the new passphrase to continue syncing.'}</p>
      <label>Vault passphrase</label><input type="password" id="crPass"><p id="crErr" class="error"></p>`,
    okText: 'Continue',
    onOk: async () => {
      $('#crErr').textContent = 'Checking…'; $('#dlgOk').disabled = true;
      const x = await window.api.cloudReauth($('#crPass').value);
      $('#dlgOk').disabled = false;
      if (!x.ok) { $('#crErr').textContent = x.error; return false; }
      return x.data;
    }
  });
  if (r) { cloudNagShown = false; toast('Sync is running again.'); }
  renderCloudPanel();
}

/* ---------- Devices ---------- */
async function cloudDevicesDialog() {
  let list;
  try { list = await call('cloudDevices'); } catch (e) { toast(e.message, 'err'); return; }
  const rows = list.map(d => `<li><div class="grow"><b>${esc(d.name)}</b> ${d.current ? '<span class="badge enc">this PC</span>' : ''}
      <div class="muted small">${d.kind === 'web' ? 'Web browser' : 'Sealpost app'} · last seen ${esc(new Date(d.lastSeen * 1000).toLocaleString())}</div></div>
      ${d.current ? '' : `<button class="btn small" data-revoke="${esc(d.id)}">Sign out</button>`}</li>`).join('');
  const p = dialog({ title: 'Devices using your vault', html: `<ul class="cloud-devices">${rows}</ul><p class="muted small">Signing a device out stops it syncing until the vault passphrase is entered there again. If a device was lost, also change the vault passphrase.</p>`, hideCancel: true, okText: 'Close' });
  $$('#dlgBody [data-revoke]').forEach(b => b.onclick = async () => {
    b.disabled = true;
    try { await call('cloudRevoke', b.dataset.revoke); b.closest('li').remove(); toast('Device signed out.'); }
    catch (e) { b.disabled = false; toast(e.message, 'err'); }
  });
  await p;
}

/* ---------- Change vault passphrase ---------- */
function cloudChangePassphrase() {
  return dialog({
    title: 'Change vault passphrase',
    html: `<label>Current vault passphrase</label><input type="password" id="ccOld">
      <label>New passphrase (at least 10 characters)</label><input type="password" id="ccP1" autocomplete="new-password">
      <label>Repeat new passphrase</label><input type="password" id="ccP2" autocomplete="new-password">
      <label class="check"><input type="checkbox" id="ccOthers"> Also sign out all other devices</label>
      <p class="muted small">Your other PCs will ask for the new passphrase once. Nothing has to be uploaded again.</p>
      <p id="ccErr" class="error"></p>`,
    okText: 'Change passphrase',
    onOk: async () => {
      if ($('#ccP1').value.length < 10) { $('#ccErr').textContent = 'Use at least 10 characters'; return false; }
      if ($('#ccP1').value !== $('#ccP2').value) { $('#ccErr').textContent = 'New passphrases do not match'; return false; }
      $('#ccErr').textContent = 'Changing…'; $('#dlgOk').disabled = true;
      const r = await window.api.cloudChangePassphrase({ current: $('#ccOld').value, next: $('#ccP1').value, signOutOthers: $('#ccOthers').checked });
      $('#dlgOk').disabled = false;
      if (!r.ok) { $('#ccErr').textContent = r.error; return false; }
      toast('Vault passphrase changed.');
      return true;
    }
  }).then(() => renderCloudPanel());
}

/* ---------- Stop syncing on this PC ---------- */
async function cloudDisconnect() {
  const ok = await confirmBox('Stop syncing on this PC', 'This PC stops syncing and signs out of the vault. Everything already on this PC stays here, and your vault on the server is not changed.', 'Stop syncing');
  if (!ok) return;
  try { await call('cloudDisconnect'); toast('Sync is off on this PC.'); } catch (e) { toast(e.message, 'err'); }
  renderCloudPanel();
}

/* ---------- First account screen: connect instead of typing everything ---------- */
$('#aCloudBtn').addEventListener('click', () => { closeModal('#acctModal'); switchView('settings'); cloudWizard(); });

/* ---------- Events from the main process ---------- */
window.api.onEvent(async ({ type, data }) => {
  // 1.11.0: Mac menu bar — Settings… (⌘,) and Select All (⌘A: messages in the list, else the text)
  if (type === 'menu') {
    if (data === 'settings') { switchView('settings'); return; }
    if (data === 'selectAll') {
      const el = document.activeElement;
      const typing = el && (/INPUT|TEXTAREA|SELECT/.test(el.tagName) || el.isContentEditable);
      const modalOpen = $$('.modal').some(m => !m.classList.contains('hidden'));
      if (!typing && !modalOpen && $('#view-mail').classList.contains('active') && state.messages.length) selectAll();
      else document.execCommand('selectAll');
    }
    return;
  }
  if (type === 'cloudsync') {
    if ($('#view-settings').classList.contains('active')) renderCloudPanel();
    if (!data.running && data.needs && !cloudNagShown) {
      cloudNagShown = true;
      toast(data.needs === 'signin' ? 'Sync paused: this PC was signed out of your vault. Sign in again under Settings → Sync.' : 'Sync paused: enter the new vault passphrase under Settings → Sync.', 'err');
    }
  }
  if (type === 'cloudsync-applied') {
    // another PC changed something — refresh what's on screen
    if (data.settings) state.settings = await call('settingsGet');
    if (data.accounts && data.accounts.length) await loadAccounts();
    else if (data.settings) await refreshAccountsQuiet();   // 1.13.2: the account order may have changed
    if (data.keys && $('#view-keys').classList.contains('active')) loadKeys();
    if (data.contacts && $('#view-contacts').classList.contains('active')) loadContacts();
    if ($('#view-settings').classList.contains('active')) loadSettingsView();
    const parts = [data.accounts && data.accounts.length ? 'accounts' : '', data.contacts ? 'contacts' : '', data.keys ? 'keys' : '', data.settings ? 'settings' : ''].filter(Boolean);
    toast('Updated from your other devices: ' + parts.join(', ') + '.');
    if (data.quarantined && data.quarantined.length) toast(`${data.quarantined.length} secret key(s) were deleted on another device. A copy was kept in the keyring\\removed-by-sync folder.`);
  }
});

/* =================================================================
 * 11b. APP LOCK (1.1.0)
 *   Settings panel, lock screen, inactivity tracking.
 *   The real protection is in the main process: while locked it
 *   answers nothing but unlock requests.
 * ================================================================= */
const IDLE_CHOICES = [[0, osText('Never (only on start / Windows lock)')], [5, '5 minutes'], [10, '10 minutes'], [15, '15 minutes'], [30, '30 minutes'], [60, '1 hour']];

async function renderLockPanel() {
  const body = $('#lockPanelBody');
  let st;
  try { st = await call('lockStatus'); } catch { return; }
  show($('#btnLockApp'), st.enabled);
  body.innerHTML = '';
  if (!st.enabled) {
    const b = document.createElement('button');
    b.className = 'btn primary'; b.textContent = 'Turn on app lock…';
    b.onclick = setupLockDialog;
    body.appendChild(b);
    return;
  }
  body.innerHTML = `
    <p>✅ App lock is <b>on</b>.</p>
    <label>Lock after inactivity</label>
    <select id="lkIdle">${IDLE_CHOICES.map(([v, t]) => `<option value="${v}">${t}</option>`).join('')}</select>
    <label class="check" id="lkHelloRow"><input type="checkbox" id="lkHello"> Allow Windows Hello (fingerprint, face or Windows PIN)</label>
    <div class="row gap wrap" style="margin-top:10px">
      <button class="btn small" id="lkNow">🔐 Lock now</button>
      <button class="btn small" id="lkChange">Change PIN…</button>
      <button class="btn small danger" id="lkOff">Turn off…</button>
    </div>`;
  $('#lkIdle').value = String(st.idleMinutes || 0);
  $('#lkHello').checked = st.hello;
  show($('#lkHelloRow'), (st.platform === 'win32' || st.hello) && !st.helloBlocked);
  if (st.helloBlocked) $('#lkHelloRow').insertAdjacentHTML('afterend', '<p class="muted small">Windows Hello is off while Offline mail is on (the offline copy is locked to your PIN).</p>');
  const update = async () => {
    try { await call('lockUpdate', { hello: $('#lkHello').checked, idleMinutes: Number($('#lkIdle').value) }); toast('App lock updated'); }
    catch (e) { toast(e.message, 'err'); }
  };
  $('#lkIdle').onchange = update;
  $('#lkHello').onchange = async () => {
    if ($('#lkHello').checked) {
      const a = await call('lockHelloAvailable');
      if (a !== 'Available') { $('#lkHello').checked = false; return toast(helloReason(a), 'warn'); }
    }
    update();
  };
  $('#lkNow').onclick = () => call('lockLockNow');
  $('#lkChange').onclick = () => dialog({
    title: 'Change PIN',
    html: `<label>Current PIN</label><input type="password" inputmode="numeric" id="lkOld">
      <label>New PIN (4–12 digits)</label><input type="password" inputmode="numeric" id="lkNew1">
      <label>Repeat new PIN</label><input type="password" inputmode="numeric" id="lkNew2"><p id="lkErr" class="error"></p>`,
    okText: 'Change PIN',
    onOk: async () => {
      if ($('#lkNew1').value !== $('#lkNew2').value) { $('#lkErr').textContent = 'New PINs do not match'; return false; }
      const r = await window.api.lockChangePin($('#lkOld').value, $('#lkNew1').value);
      if (!r.ok) { $('#lkErr').textContent = r.error; return false; }
      toast('PIN changed'); return true;
    }
  });
  $('#lkOff').onclick = () => dialog({
    title: 'Turn off app lock',
    html: (state.offline && state.offline.enabled ? '<p class="inline-warn small">Offline mail is encrypted to this PIN, so turning off App lock also <b>deletes the offline copy</b> from this PC (your mail stays on the server).' + (state.offline.outbox ? ' <b>Send or delete the messages in the Outbox first.</b>' : '') + '</p>' : '') +
      '<label>Enter your PIN</label><input type="password" inputmode="numeric" id="lkOffPin"><p id="lkErr" class="error"></p>',
    okText: 'Turn off', danger: true,
    onOk: async () => {
      const r = await window.api.lockDisable($('#lkOffPin').value);
      if (!r.ok) { $('#lkErr').textContent = r.error; return false; }
      toast('App lock turned off'); renderLockPanel(); return true;
    }
  });
}

function helloReason(a) {
  return {
    DeviceNotPresent: 'Windows Hello: no fingerprint reader, camera or Hello PIN on this PC.',
    NotConfiguredForUser: 'Windows Hello is not set up. Set it up in Windows Settings → Accounts → Sign-in options.',
    DisabledByPolicy: 'Windows Hello is disabled by your organization.',
    DeviceBusy: 'Windows Hello is busy. Try again.',
    Unsupported: 'Windows Hello is not available here.'
  }[a] || 'Windows Hello is not available (' + a + ').';
}

async function setupLockDialog() {
  const isWin = (await call('lockStatus')).platform === 'win32';
  await dialog({
    title: 'Turn on app lock',
    html: `<p>Choose a PIN. You'll need it (or Windows Hello) to open Sealpost.</p>
      <label>PIN (4–12 digits)</label><input type="password" inputmode="numeric" id="lkPin1">
      <label>Repeat PIN</label><input type="password" inputmode="numeric" id="lkPin2">
      <label>Lock after inactivity</label>
      <select id="lkIdle2">${IDLE_CHOICES.map(([v, t]) => `<option value="${v}" ${v === 15 ? 'selected' : ''}>${t}</option>`).join('')}</select>
      ${isWin ? '<label class="check"><input type="checkbox" id="lkHello2"> Also allow Windows Hello (fingerprint, face or Windows PIN)</label>' : ''}
      <p class="muted small">Forgot the PIN? You can always unlock with the passphrase of any of your PGP keys.</p>
      <p id="lkErr" class="error"></p>`,
    okText: 'Turn on',
    onOk: async () => {
      if ($('#lkPin1').value !== $('#lkPin2').value) { $('#lkErr').textContent = 'PINs do not match'; return false; }
      let hello = !!($('#lkHello2') && $('#lkHello2').checked);
      if (hello) {
        $('#lkErr').textContent = 'Checking Windows Hello…';
        const a = await call('lockHelloAvailable');
        if (a !== 'Available') { $('#lkErr').textContent = helloReason(a); return false; }
      }
      const r = await window.api.lockSetup({ pin: $('#lkPin1').value, hello, idleMinutes: Number($('#lkIdle2').value) });
      if (!r.ok) { $('#lkErr').textContent = r.error; return false; }
      toast('App lock is on'); return true;
    }
  });
  renderLockPanel();
}

$('#btnLockApp').addEventListener('click', () => call('lockLockNow'));

/* ---------- Lock screen ---------- */
let lockResolve = null;
function showLockScreen() {
  if (!$('#lockScreen').classList.contains('hidden')) return lockWait;
  $$('.modal').forEach(m => m.classList.add('hidden'));
  show($('#lockScreen'), true);
  show($('#lockPinArea'), true); show($('#lockPassArea'), false);
  $('#lockErr').textContent = '';
  $('#lockPin').value = ''; $('#lockPass').value = '';
  call('lockStatus').then(st => {
    show($('#lockHello'), st.hello);
    if (st.hello) tryHello(); else setTimeout(() => $('#lockPin').focus(), 50);
  }).catch(() => {});
  lockWait = new Promise(r => { lockResolve = r; });
  return lockWait;
}
let lockWait = Promise.resolve();

function unlocked() {
  show($('#lockScreen'), false);
  if (lockResolve) { lockResolve(); lockResolve = null; }
}

async function tryHello() {
  $('#lockErr').textContent = 'Waiting for Windows Hello…';
  const r = await window.api.lockUnlockHello();
  if (r.ok) return unlocked();
  $('#lockErr').textContent = r.error + ' — or enter your PIN.';
  $('#lockPin').focus();
}

async function tryPin() {
  const r = await window.api.lockUnlockPin($('#lockPin').value);
  if (r.ok) return unlocked();
  $('#lockErr').textContent = r.error;
  $('#lockPin').select();
}
async function tryPass() {
  $('#lockErr').textContent = 'Checking…';
  const r = await window.api.lockUnlockPassphrase($('#lockPass').value);
  if (r.ok) return unlocked();
  $('#lockErr').textContent = r.error;
  $('#lockPass').select();
}
$('#lockPinGo').addEventListener('click', tryPin);
$('#lockPin').addEventListener('keydown', e => { if (e.key === 'Enter') tryPin(); });
$('#lockPassGo').addEventListener('click', tryPass);
$('#lockPass').addEventListener('keydown', e => { if (e.key === 'Enter') tryPass(); });
$('#lockHello').addEventListener('click', tryHello);
$('#lockForgot').addEventListener('click', () => {
  const toPass = $('#lockPassArea').classList.contains('hidden');
  show($('#lockPassArea'), toPass); show($('#lockPinArea'), !toPass);
  $('#lockForgot').textContent = toPass ? 'Use PIN instead' : 'Forgot PIN? Use a key passphrase';
  $('#lockErr').textContent = '';
  (toPass ? $('#lockPass') : $('#lockPin')).focus();
});

// Tell the main process you're active (for "lock after inactivity"), at most every 20 s
let lastPing = 0;
['mousemove', 'keydown', 'mousedown', 'wheel'].forEach(ev => document.addEventListener(ev, () => {
  if (Date.now() - lastPing > 20000 && $('#lockScreen').classList.contains('hidden')) { lastPing = Date.now(); window.api.lockActivity(); }
}, { passive: true }));

/* =================================================================
 * 12. KEYBOARD SHORTCUTS + STARTUP
 * ================================================================= */
document.addEventListener('keydown', e => {
  const typing = /INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName);
  const modalOpen = $$('.modal').some(m => !m.classList.contains('hidden'));
  if (e.key === 'Escape' && modalOpen && $('#passModal').classList.contains('hidden')) {
    const open = $$('.modal').filter(m => !m.classList.contains('hidden')).pop();
    if (open && open._cancel) open._cancel();                       // generic dialog: cancel
    else if (open && open.id === 'composeModal') closeComposer();    // composer: save draft / discard
    else if (open) open.classList.add('hidden');
  }
  if (MOD(e) && e.key === 'Enter' && !$('#composeModal').classList.contains('hidden')) { e.preventDefault(); sendMessage(); }
  if (modalOpen || typing) return;
  if (e.key === 'F5') { e.preventDefault(); refreshAll(); }
  if (MOD(e) && e.key.toLowerCase() === 'n') { e.preventDefault(); openComposer(); }
  if (!$('#view-mail').classList.contains('active')) return;
  // 1.7.0: Ctrl+A selects all, Esc clears, Delete works on the selection
  if (MOD(e) && e.key.toLowerCase() === 'a' && state.messages.length) { e.preventDefault(); selectAll(); return; }
  if (e.key === 'Escape' && (state.selected.size || state.selectMode)) { clearSelection(); return; }
  if (e.key === 'Delete' && state.selected.size) { bulkDelete([...state.selected]); return; }
  if (e.key === 'Delete') deleteSelected();
  // 1.6.0: Ctrl+Q read, Ctrl+U unread (as in Outlook)
  if (e.ctrlKey && (e.key.toLowerCase() === 'q' || e.key.toLowerCase() === 'u') && state.selectedUid) { e.preventDefault(); setSeen([state.selectedUid], e.key.toLowerCase() === 'q'); }
  if (MOD(e) && e.key.toLowerCase() === 'r' && state.view) { e.preventDefault(); openComposer({ mode: 'reply', view: state.view }); }
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp' || e.key === 'j' || e.key === 'k') {
    const order = state.visible || state.messages.map(m => m.uid);   // 1.10.0: what the list shows
    const i = order.indexOf(state.selectedUid);
    const k = order[(e.key === 'ArrowDown' || e.key === 'j') ? i + 1 : Math.max(0, i - 1)];
    if (k != null) { e.preventDefault(); openMessage(k); document.querySelector(`.msg[data-uid="${k}"]`)?.scrollIntoView({ block: 'nearest' }); }
  }
});

(async function start() {
  try {
    // 1.1.0: if the app lock is on, nothing loads until you unlock
    const lk = await call('lockStatus');
    show($('#btnLockApp'), lk.enabled);
    if (lk.locked) await showLockScreen();
    state.settings = await call('settingsGet');
    try { state.push = await call('pushStatus'); } catch { /* ignore */ }   // 1.2.0
    try { const st = await call('offlineStatus'); (st.offlineAccounts || []).forEach(a => state.offlineAcc.add(a)); } catch { /* ignore */ } // 1.3.0
    refreshOutbox();
    await loadAccounts();
    checkExpiry(true); // 1.1.0: warn about keys expiring within 30 days
    if (!state.accounts.length) {
      switchView('settings');
      setTimeout(() => openAccountEditor(), 200);
    }
  } catch (e) { toast('Startup error: ' + e.message, 'err'); }
})();
