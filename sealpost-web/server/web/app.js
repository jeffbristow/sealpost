/* =====================================================================
 * Sealpost Web — app.js  (main screen)
 * ---------------------------------------------------------------------
 * Sections:
 *   1.  State + shared context for the other screens
 *   2.  Saving to the vault (contacts, keys, passphrases) + keyring refresh
 *   3.  Sign in / start up / sign out / idle sign-out
 *   3b. iPhone app (1.5.0): PIN unlock, lock, "This device" settings,
 *       install hint, app icon badge, offline shell (sw.js)
 *       + Face ID unlock (1.6.0, faceid.js)
 *   4.  Views: Mail, Contacts, Keys
 *   5.  Sidebar: accounts + folders
 *   6.  Message list (paging, search, refresh)
 *   7.  Reader: open, PGP banners, attachments, body
 *   8.  Reader actions (reply, forward, unread, flag, move, delete,
 *       add contact, import keys, source)
 *   8b. Read / unread, mark folder read, right-click menus (1.3.0)
 *   8c. Selecting several messages (1.4.0)
 *   9.  Phone layout (folder drawer, back button)
 *   10. Background refresh (new mail, vault changes) + keyboard
 *
 * The composer lives in composer.js, Contacts + Keys in people.js,
 * PGP Tools in tools.js, Settings + accounts + backup import in
 * settings.js, small shared helpers in ui.js.
 * ===================================================================== */

import * as vault from './vault.js?v=1.10.0';
import { Keyring } from './pgp.js?v=1.10.0';
import { readMessage } from './reader.js?v=1.10.0';
import { $, $$, esc, show, addr, addrShort, fmtDate, fmtSize, toast, loading, download, dialog, confirmBox, promptPassphrase, withPassphrase } from './ui.js?v=1.10.0';
import { initComposer } from './composer.js?v=1.10.0';
import { initPeople } from './people.js?v=1.10.0';
import { initTools } from './tools.js?v=1.10.0';
import { initSettings } from './settings.js?v=1.10.0';
import { faceSupported, enableFace, pinFromFace, faceName } from './faceid.js?v=1.10.0';   // 1.6.0
import { initUpdates } from './update.js?v=1.10.0';   // 1.10.0

/* =================================================================
 * 1. STATE + CONTEXT
 * ================================================================= */
const keyring = new Keyring();
const state = {
  vault: null,              // { accounts, contacts, keys, passphrases, settings, items, seqs, seq }
  folders: {},              // accId -> [folders]
  folderErrors: {},         // accId -> message
  cur: { accId: null, folder: 'INBOX', page: 0, search: '' },
  messages: [], total: 0, hasMore: false,
  selectedUid: null,
  view: null,               // open message view
  listToken: 0,             // ignore late answers after switching folders
  raw: new Map(),           // "acc|folder|uid" -> bytes  (small cache, this tab only)
  remoteAllowedFor: null,
  screen: 'mail',
  selected: new Set(),      // 1.4.0: messages ticked for a bulk action
  selectMode: false,
  anchor: null,             // last clicked row (for Shift-click ranges)
  expanded: new Set()       // 1.8.0: conversations opened up in the list
};
const account = id => state.vault.accounts.find(a => a.id === id);
const curAccount = () => account(state.cur.accId);
const msgKey = uid => { const l = loc(uid); return `${l.accId}|${l.folder}|${l.uid}`; };

/* ---------- 1.8.0: All Inboxes + where a message lives ----------
 * In "All Inboxes" (state.cur.accId === UNIFIED) each message carries its
 * own account and its list key is "accountId:uid". loc() turns a key
 * back into { accId, folder, uid }; perBox() runs a mail.php call once
 * per account/folder for a mixed selection. */
const UNIFIED = '__all__';
const isUnified = () => state.cur.accId === UNIFIED;
function loc(key) {
  const m = state.messages.find(x => x.uid === key);
  return m ? { accId: m.accId || state.cur.accId, folder: m.folder || state.cur.folder, uid: m.realUid ?? m.uid }
    : { accId: state.cur.accId, folder: state.cur.folder, uid: key };
}
const boxCall = (accId, action, body, opts) => vault.mail(action, { account: vault.imapDetails(account(accId)), ...body }, opts);
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
const rowKey = row => (isUnified() ? row.dataset.uid : Number(row.dataset.uid));
const curFolderInfo = () => (state.folders[state.cur.accId] || []).find(f => f.path === state.cur.folder) || null;
const isDraftsFolder = () => { const f = curFolderInfo(); return !!(f && f.specialUse === '\\Drafts') || /^(inbox[./])?drafts?$/i.test(state.cur.folder); };

/** Call mail.php for the current account (connection details come from the vault). */
const mailCall = (action, body, opts) => vault.mail(action, { account: vault.imapDetails(curAccount()), ...body }, opts);

// shared with composer.js and people.js
const ctx = {
  state, keyring, vault, account, curAccount, mailCall,
  save: changes => saveToVault(changes),
  loadMessages: o => loadMessages(o),
  loadFolders: id => loadFolders(id),
  renderList: () => renderList(),
  isDraftsFolder,
  switchView: v => switchView(v),
  openComposer: o => composer.openComposer(o),
  loadAccounts: () => loadAccounts(),                 // 1.4.0
  lookupKey: email => people.lookupDialog(email),     // 1.4.0
  importKeys: text => people.importKeys(text)         // 1.4.0
};
const composer = initComposer(ctx);
const people = initPeople(ctx);
const tools = initTools(ctx);
const settings = initSettings(ctx);
const updates = initUpdates(ctx);   // 1.10.0

/* =================================================================
 * 2. SAVING TO THE VAULT + KEYRING REFRESH
 *    Changes made here sync to Sealpost on your PCs as well.
 * ================================================================= */
async function reloadKeyring() {
  await keyring.load(state.vault.keys, state.vault.settings, state.vault.passphrases);
  keyring.setPinnedLookup(email => {
    const c = state.vault.contacts.find(x => (x.emails || []).includes(email));
    return c && c.keyFp ? c.keyFp : null;
  });
}

async function saveToVault(changes) {
  state.vault = await vault.saveItems(state.vault, changes);
  await reloadKeyring();
  if (state.view) { state.view.sender = senderCheck(state.view); renderPgpBanner(state.view); }
  return state.vault;
}

/* =================================================================
 * 3. SIGN IN / START UP / SIGN OUT
 * ================================================================= */
const IDLE_MINUTES = 30;
let lastActivity = Date.now();
let timers = [];

/** Stop everything that belongs to an open vault (used by sign out and lock). */
function closeVault() {
  timers.forEach(clearInterval); timers = [];
  keyring.lockAll();
  composer.reset();
  state.vault = null; state.raw.clear(); state.view = null;
  knownPin = null;
  show($('#app'), false);
  loading(null);
  setBadge(0);
}

/** Passphrase screen — or the PIN screen when this phone has PIN unlock (1.5.0). */
function showSignIn(message = '', { passphrase = false } = {}) {
  closeVault();
  const dev = vault.pinDevice();
  if (dev && !passphrase) return showPin(message);
  show($('#pinScreen'), false);
  show($('#signin'), true);
  show($('#installHint'), isIOS() && !isStandalone());
  $('#siErr').textContent = message;
  $('#siPass').value = '';
  if (dev && !$('#siUser').value) $('#siUser').value = dev.username;
  setTimeout(() => ($('#siUser').value ? $('#siPass') : $('#siUser')).focus(), 30);
}

vault.setSignedOutHandler(msg => showSignIn(msg || 'You were signed out. Sign in again.'));

$('#signinForm').addEventListener('submit', async e => {
  e.preventDefault();
  $('#siErr').textContent = '';
  $('#siGo').disabled = true;
  loading('Unlocking your vault…');
  try {
    await vault.signIn($('#siUser').value, $('#siPass').value);
    $('#siPass').value = '';
    await startApp();
    offerPin();
  } catch (err) {
    loading(null);
    $('#siErr').textContent = err.message;
  } finally { $('#siGo').disabled = false; }
});

async function startApp() {
  loading('Opening your vault…');
  state.vault = await vault.loadVault();
  await reloadKeyring();
  show($('#signin'), false);
  show($('#pinScreen'), false);
  show($('#app'), true);
  loading(null);
  $('#userLabel').textContent = 'Vault: ' + vault.currentUser();
  show($('#btnLockApp'), vault.pinActive());
  lastActivity = Date.now();
  timers.push(setInterval(backgroundRefresh, 120000));
  timers.push(setInterval(refreshVault, 300000));
  timers.push(setInterval(checkIdle, 30000));
  switchView('mail');
  updates.start();   // 1.10.0: a newer Sealpost Server? (doesn't hold up the mail)
  await loadAccounts();
}

/** 30 minutes without use: lock (PIN devices) or sign out (everyone else). */
function checkIdle() {
  if (!state.vault || Date.now() - lastActivity <= IDLE_MINUTES * 60000) return;
  if (vault.pinActive()) lockApp(`Locked after ${IDLE_MINUTES} minutes without activity.`, { ask: false });
  else signOut(`Signed out after ${IDLE_MINUTES} minutes without activity.`, { ask: false });
}

async function signOut(message = '', { ask = true } = {}) {
  if (ask && composer.isOpen() && !(await confirmBox('Sign out', 'The message you are writing will be lost unless you save it as a draft first. Sign out anyway?', 'Sign out', true))) return;
  if (ask && vault.pinActive() && !(await confirmBox('Sign out', 'Signing out also turns off PIN unlock on this device — next time you\'ll need your vault passphrase. (Use 🔐 Lock to keep the PIN.)', 'Sign out', true))) return;
  await vault.signOutEverywhere();
  showSignIn(message, { passphrase: true });
}

['pointerdown', 'keydown', 'wheel', 'touchstart'].forEach(ev => window.addEventListener(ev, () => { lastActivity = Date.now(); }, { passive: true }));
$('#btnSignOut').addEventListener('click', () => signOut('Signed out.'));
$('#btnLockKeys').addEventListener('click', () => {
  keyring.lockAll();
  toast(keyring.remembered.size ? 'Private keys locked. Keys remembered on all your devices still unlock automatically.' : 'Private keys locked in this tab.');
});

/* =================================================================
 * 3b. IPHONE APP (1.5.0)
 * ================================================================= */
const isIOS = () => /iPhone|iPad|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
const isStandalone = () => navigator.standalone === true || window.matchMedia('(display-mode: standalone)').matches;
document.documentElement.classList.toggle('standalone', isStandalone());

// --- PIN screen (+ Face ID, 1.6.0) ---
let knownPin = null;       // the PIN typed in this session — only so Face ID can be turned on without asking again
let faceAuto = false;      // try Face ID by itself once when the app starts

function showPin(message = '') {
  const dev = vault.pinDevice();
  show($('#signin'), false);
  show($('#pinScreen'), true);
  $('#pinWho').textContent = 'Vault: ' + dev.username;
  $('#pinErr').textContent = message;
  $('#pinInput').value = '';
  const face = !!dev.face;
  show($('#pinFace'), face);
  $('#pinFace').textContent = `🙂 Unlock with ${faceName()}`;
  $('#pinGo').classList.toggle('primary', !face);
  if (face && faceAuto) { faceAuto = false; setTimeout(() => unlockWithFace(true), 150); }
  else if (!face) setTimeout(() => $('#pinInput').focus(), 30);
}

/** PIN -> vault (typed, or produced by Face ID). */
async function unlockPin(pin, viaFace = false) {
  $('#pinErr').textContent = '';
  $('#pinGo').disabled = $('#pinFace').disabled = true;
  loading('Unlocking…');
  const who = (vault.pinDevice() || {}).username || '';
  try {
    await vault.unlockWithPin(pin);
    knownPin = pin;
    $('#pinInput').value = '';
    await startApp();
  } catch (err) {
    loading(null);
    $('#pinInput').value = '';
    if (err.code === 'pin_reset') { $('#siUser').value = who; showSignIn(err.message, { passphrase: true }); }
    else if (viaFace && err.code === 'bad_pin') {
      // the PIN kept for Face ID is out of date: drop it, ask for the PIN
      vault.setDeviceFace(null); show($('#pinFace'), false); $('#pinGo').classList.add('primary');
      $('#pinErr').textContent = `${faceName()} needs to be set up again — enter your PIN. (${err.message})`;
    } else { $('#pinErr').textContent = err.message; $('#pinInput').focus(); }
  } finally { $('#pinGo').disabled = $('#pinFace').disabled = false; }
}

async function unlockWithFace(silent = false) {
  const dev = vault.pinDevice();
  if (!dev || !dev.face) return;
  let pin;
  try { pin = await pinFromFace(dev.face); }
  catch (e) {
    if (e.code === 'FACE_STALE') { vault.setDeviceFace(null); show($('#pinFace'), false); }
    if (!silent && e.code !== 'CANCELLED') $('#pinErr').textContent = e.message;
    $('#pinInput').focus();
    return;
  }
  await unlockPin(pin, true);
}

$('#pinForm').addEventListener('submit', e => {
  e.preventDefault();
  const pin = $('#pinInput').value.trim();
  if (pin) unlockPin(pin);
});
$('#pinFace').addEventListener('click', () => unlockWithFace(false));
$('#pinUsePass').addEventListener('click', () => showSignIn('', { passphrase: true }));

// --- lock (keeps PIN unlock) ---
async function lockApp(message = 'Locked.', { ask = true } = {}) {
  if (ask && composer.isOpen() && !(await confirmBox('Lock', 'The message you are writing will be lost unless you save it as a draft first. Lock anyway?', 'Lock', true))) return;
  await vault.lock();
  showSignIn(message);
}
$('#btnLockApp').addEventListener('click', () => lockApp('Locked.'));

// --- set up a PIN ---
const pinFields = `
  <label for="pinNew">New PIN (6–12 digits)</label>
  <input id="pinNew" class="pin-input" type="password" inputmode="numeric" pattern="[0-9]*" maxlength="12" autocomplete="off">
  <label for="pinNew2">Same PIN again</label>
  <input id="pinNew2" class="pin-input" type="password" inputmode="numeric" pattern="[0-9]*" maxlength="12" autocomplete="off">
  <p id="pinNewErr" class="error"></p>`;

async function setupPinDialog(intro) {
  let chosen = null;
  const ok = await dialog({
    title: 'Unlock with a PIN',
    html: `<p>${intro}</p>
      <p class="muted small">Your vault stays encrypted on this device. The PIN only works together with a secret on your server, and 5 wrong PINs turn it off. Sealpost locks itself after ${IDLE_MINUTES} minutes without use; a device unused for 30 days must sign in with the passphrase again.</p>
      ${pinFields}`,
    okText: 'Turn on PIN',
    cancelText: 'Not now',
    onOk: async () => {
      const a = $('#pinNew').value.trim(), b = $('#pinNew2').value.trim();
      const err = t => { $('#pinNewErr').textContent = t; return false; };
      if (!/^\d{6,12}$/.test(a)) return err('Use 6 to 12 digits.');
      if (/^(\d)\1+$/.test(a) || '01234567890123456789'.includes(a) || '98765432109876543210'.includes(a)) return err('That PIN is too easy to guess.');
      if (a !== b) return err('The two PINs are different.');
      try { await vault.setupPin(a); chosen = a; return true; } catch (e) { return err(e.message); }
    }
  });
  if (!ok) return;
  knownPin = chosen;
  toast('PIN unlock is on for this device.');
  show($('#btnLockApp'), true);
  renderDevicePanel();
  // 1.6.0: a new PIN replaces the Face ID data, so offer Face ID (again)
  if (await faceSupported()) offerFace();
}

/** After a passphrase sign-in in the home-screen app: offer a PIN. */
function offerPin() {
  if (!isStandalone() || vault.pinActive()) return;
  setupPinDialog('Keep Sealpost signed in on this iPhone and open it with a PIN instead of your vault passphrase?');
}

// --- Face ID (1.6.0) ---
async function offerFace() {
  const name = faceName();
  const ok = await dialog({
    title: `Unlock with ${name}?`,
    html: `<p>Open Sealpost with ${name} instead of typing your PIN.</p>
      <p class="muted small">This saves a Sealpost passkey in your iCloud Keychain. Only a successful ${name} scan lets it unlock your PIN on this phone; the PIN stays as the backup.</p>`,
    okText: `Use ${name}`, cancelText: 'Not now'
  });
  if (ok) turnOnFace();
}

/** The PIN is needed once to set Face ID up; checked with the server (counts as a try if wrong). */
async function askPin() {
  return dialog({
    title: 'Enter your PIN',
    html: `<p>Enter this device's PIN to set up ${faceName()}.</p>
      <label for="pinCheck">PIN</label>
      <input id="pinCheck" class="pin-input" type="password" inputmode="numeric" pattern="[0-9]*" maxlength="12" autocomplete="off">
      <p id="pinCheckErr" class="error"></p>`,
    okText: 'Continue',
    onOk: async () => {
      const pin = $('#pinCheck').value.trim();
      try { await vault.unlockWithPin(pin); return pin; }      // proves the PIN (and refreshes this session)
      catch (e) {
        if (e.code === 'pin_reset') { show($('#dlgModal'), false); showSignIn(e.message, { passphrase: true }); return null; }
        $('#pinCheckErr').textContent = e.message; return false;
      }
    }
  });
}

async function turnOnFace() {
  const pin = knownPin || await askPin();
  if (!pin) return;
  knownPin = pin;
  try {
    const face = await enableFace(pin, vault.currentUser());
    vault.setDeviceFace(face);
    toast(`${faceName()} unlock is on for this device.`);
  } catch (e) { if (e.code !== 'CANCELLED') toast(e.message, 'err'); }
  renderDevicePanel();
}

// --- Settings -> This device ---
async function renderDevicePanel() {
  const box = $('#stDevice');
  if (!box) return;
  const on = vault.pinActive();
  const dev = vault.pinDevice();
  const faceOn = !!(on && dev && dev.face);
  const canFace = on && !faceOn && await faceSupported();
  const name = faceName();
  const how = isStandalone() ? 'Running as an app from the home screen.'
    : isIOS() ? 'To install: tap <b>Share</b> ⬆︎ in Safari, then <b>Add to Home Screen</b>. Open it from the icon and sign in there — the app keeps its own sign-in, separate from Safari.'
      : 'On an iPhone: open this page in Safari, tap <b>Share</b>, then <b>Add to Home Screen</b>.';
  box.innerHTML = `
    <p class="small">${how}</p>
    <p class="small">PIN unlock: <b>${on ? 'on' : 'off'}</b>${on ? ` · ${esc(name)}: <b>${faceOn ? 'on' : 'off'}</b>` : ''}</p>
    <div class="row-btns">${on
      ? `${faceOn ? `<button id="stFaceOff" class="btn small" type="button">Turn off ${esc(name)}</button>` : canFace ? `<button id="stFaceOn" class="btn small primary" type="button">Turn on ${esc(name)}…</button>` : ''}
         <button id="stPinChange" class="btn small" type="button">Change PIN</button><button id="stPinOff" class="btn small danger" type="button">Turn off PIN</button>`
      : '<button id="stPinOn" class="btn small primary" type="button">Turn on PIN unlock…</button>'}</div>
    ${on && !faceOn && !canFace ? `<p class="muted small">${esc(name)} unlock isn't available in this browser (on iPhone it needs iOS 18 or newer).</p>` : ''}`;
  const btn = id => $(id);
  if (btn('#stPinOn')) btn('#stPinOn').onclick = () => setupPinDialog('Open Sealpost on this device with a PIN instead of your vault passphrase.');
  if (btn('#stPinChange')) btn('#stPinChange').onclick = () => setupPinDialog('Choose a new PIN for this device.' + (faceOn ? ` (${esc(name)} is set up again afterwards.)` : ''));
  if (btn('#stFaceOn')) btn('#stFaceOn').onclick = () => turnOnFace();
  if (btn('#stFaceOff')) btn('#stFaceOff').onclick = () => { vault.setDeviceFace(null); toast(`${name} unlock is off. (The Sealpost passkey can be deleted in the iPhone's Passwords app.)`); renderDevicePanel(); };
  if (btn('#stPinOff')) btn('#stPinOff').onclick = async () => {
    try { await vault.removePin(); toast('PIN unlock is off. Closing Sealpost now signs you out.'); }
    catch (e) { toast(e.message, 'err'); }
    show($('#btnLockApp'), false);
    renderDevicePanel();
  };
}

// --- unread count on the home-screen icon (iOS 16.4+, when allowed) ---
function setBadge(n) {
  try {
    if (!('setAppBadge' in navigator)) return;
    if (n > 0) navigator.setAppBadge(n).catch(() => {}); else navigator.clearAppBadge().catch(() => {});
  } catch { /* not supported */ }
}
function updateBadge() {
  if (!state.vault) return;
  let n = 0;
  for (const a of state.vault.accounts) {
    const inbox = (state.folders[a.id] || []).find(f => f.specialUse === '\\Inbox' || f.path === 'INBOX');
    if (inbox) n += inbox.unseen || 0;
  }
  setBadge(n);
}

// --- offline app shell: the app opens instantly; mail itself is never cached ---
if ('serviceWorker' in navigator && (location.protocol === 'https:' || location.hostname === 'localhost' || location.hostname === '127.0.0.1')) {
  navigator.serviceWorker.register('sw.js', { scope: './' }).catch(() => { /* optional */ });
}

// back in the app after a while (iPhone apps are paused in the background)
document.addEventListener('visibilitychange', () => { if (!document.hidden) checkIdle(); });

// start: reuse this tab's session, or ask for the PIN / passphrase
(async () => {
  faceAuto = true;   // 1.6.0: offer Face ID straight away when the app opens
  if (!vault.loadSession()) { showSignIn(); return; }
  faceAuto = false;
  try { await startApp(); }
  catch (e) { if (e.code !== 'not_signed_in') showSignIn(e.message); }
})();

/* =================================================================
 * 4. VIEWS — Mail | Contacts | Keys
 * ================================================================= */
function switchView(name) {
  state.screen = name;
  $('#app').dataset.screen = name;
  $$('.nav-btn[data-view]').forEach(b => b.classList.toggle('active', b.dataset.view === name));
  if (name === 'contacts') people.showContacts();
  if (name === 'keys') people.showKeys();
  if (name === 'tools') tools.showTools();
  if (name === 'settings') { settings.showSettings(); renderDevicePanel(); updates.renderPanel(); }
  if (state.vault) renderTree();
  closeNav();
}
$$('.nav-btn[data-view]').forEach(b => b.addEventListener('click', () => switchView(b.dataset.view)));
$('#btnCompose').addEventListener('click', () => { closeNav(); composer.openComposer(); });

/* =================================================================
 * 5. SIDEBAR — ACCOUNTS + FOLDERS
 * ================================================================= */
async function loadAccounts() {
  const accs = state.vault.accounts;
  if (!accs.length) {
    renderTree();
    $('#messageList').innerHTML = `<div class="list-empty">No mail accounts in your vault yet.<br><br>Add one in Sealpost on your PC — it appears here after it syncs.</div>`;
    return;
  }
  if (state.cur.accId === UNIFIED && accs.length < 2) state.cur.accId = null;   // 1.8.0
  if (!state.cur.accId || (state.cur.accId !== UNIFIED && !account(state.cur.accId))) Object.assign(state.cur, { accId: accs[0].id, folder: 'INBOX' });
  renderTree();
  selectFolder(state.cur.accId, state.cur.folder);
  await Promise.all(accs.map(a => loadFolders(a.id)));
}

async function loadFolders(accId) {
  if (accId === UNIFIED) return Promise.all(state.vault.accounts.map(a => loadFolders(a.id)));   // 1.8.0
  try {
    const r = await vault.mail('folders', { account: vault.imapDetails(account(accId)) });
    state.folders[accId] = r.folders;
    delete state.folderErrors[accId];
  } catch (e) {
    if (!state.folders[accId]) state.folders[accId] = [];
    state.folderErrors[accId] = e.message;
  }
  renderTree();
  if (accId === state.cur.accId) {
    const f = curFolderInfo();
    if (f) $('#folderTitle').textContent = f.name;
  }
}

const folderIcon = f => ({ '\\Inbox': '📥', '\\Sent': '📤', '\\Drafts': '📝', '\\Trash': '🗑', '\\Junk': '⚠', '\\Archive': '🗄', '\\Flagged': '⚑', '\\All': '📚' }[f.specialUse] || '📁');

function renderTree() {
  const tree = $('#accountTree');
  tree.innerHTML = '';
  const accs = state.vault.accounts, multi = accs.length > 1;
  const onMail = state.screen === 'mail';

  // 1.8.0: favourites — All Inboxes (2+ accounts) and pinned folders
  const pins = [];
  for (const a of accs) for (const p of a.pinnedFolders || []) {
    const f = (state.folders[a.id] || []).find(x => upath(x) === p);
    pins.push({ a, f: f || { path: p, name: p.split(/[/.]/).pop(), specialUse: null, unseen: 0 } });
  }
  if (multi || pins.length) {
    const lbl = document.createElement('div');
    lbl.className = 'acct-label';
    lbl.textContent = 'Favorites';
    tree.appendChild(lbl);
    if (multi) {
      const unread = accs.reduce((n, a) => n + (((state.folders[a.id] || []).find(f => f.path.toUpperCase() === 'INBOX') || {}).unseen || 0), 0);
      const el = document.createElement('button');
      el.type = 'button';
      el.className = 'folder fav' + (onMail && isUnified() ? ' active' : '');
      el.innerHTML = `<span aria-hidden="true">📬</span><span class="name">All Inboxes</span>${unread ? `<span class="count">${unread}</span>` : ''}`;
      el.onclick = () => { switchView('mail'); selectFolder(UNIFIED, 'INBOX'); };
      el.oncontextmenu = e => { e.preventDefault(); showMenu(e, [{ label: '✓ Mark all inboxes as read', run: () => markFolderRead(UNIFIED, 'INBOX') }]); };
      tree.appendChild(el);
    }
    for (const { a, f } of pins) tree.appendChild(folderRow(a, f, { pinned: true, multi }));
  }

  for (const a of accs) {
    const lbl = document.createElement('div');
    lbl.className = 'acct-label';
    lbl.innerHTML = `<span class="acct-name">${esc(a.name ? `${a.name} · ${a.email}` : a.email)}</span><button type="button" class="acct-add" title="New folder">＋</button><button type="button" class="acct-more" title="Account options">⋯</button>`;
    lbl.title = a.email;
    const menu = e => { e.preventDefault(); e.stopPropagation(); showMenu(e, [
      { label: '＋ New folder…', run: () => newFolderDialog(a.id, null) },
      { label: (a.conversationView ? '☑' : '☐') + ' Conversation view', run: () => setConversation(a.id, !a.conversationView) }
    ]); };
    lbl.querySelector('.acct-add').onclick = e => { e.stopPropagation(); newFolderDialog(a.id, null); };
    lbl.querySelector('.acct-more').onclick = menu;
    lbl.oncontextmenu = menu;
    tree.appendChild(lbl);
    if (state.folderErrors[a.id]) {
      const er = document.createElement('div');
      er.className = 'acct-error'; er.textContent = state.folderErrors[a.id];
      tree.appendChild(er);
    }
    for (const f of state.folders[a.id] || []) tree.appendChild(folderRow(a, f, {}));
  }
  updateBadge();   // 1.5.0
}

/** One folder line (also used for pinned folders). ⋯ / right-click = folder menu. */
function folderRow(a, f, { pinned = false, multi = false } = {}) {
  const el = document.createElement('div');
  el.className = 'folder' + (pinned ? ' fav' : '') + (state.screen === 'mail' && a.id === state.cur.accId && f.path === state.cur.folder ? ' active' : '');
  el.setAttribute('role', 'button'); el.tabIndex = 0;
  if (!pinned) el.style.paddingLeft = (10 + (f.depth || 0) * 14) + 'px';
  const label = pinned && multi ? `${esc(f.name)} <span class="muted small">· ${esc(a.email)}</span>` : esc(f.name);
  el.innerHTML = `<span aria-hidden="true">${pinned ? '📌' : folderIcon(f)}</span><span class="name">${label}</span>${f.unseen ? `<span class="count">${f.unseen}</span>` : ''}<button type="button" class="folder-more" title="Folder options">⋯</button>`;
  const menu = e => { e.preventDefault(); e.stopPropagation(); showMenu(e, folderMenuItems(a, f)); };
  el.querySelector('.folder-more').onclick = menu;
  el.oncontextmenu = menu;
  if (f.noselect) { el.classList.add('noselect'); el.title = 'This folder only holds other folders'; return el; }
  el.onclick = () => { switchView('mail'); selectFolder(a.id, f.path); };
  el.onkeydown = e => { if (e.key === 'Enter') el.click(); };
  // drop messages here to move them
  el.ondragover = e => { if (dragInfo && dragInfo.accIds.size === 1 && dragInfo.accIds.has(a.id) && dragInfo.folder !== f.path) { e.preventDefault(); el.classList.add('drop'); } };
  el.ondragleave = () => el.classList.remove('drop');
  el.ondrop = e => { e.preventDefault(); el.classList.remove('drop'); if (dragInfo) moveMessages(dragInfo.keys, a.id, f.path); };
  return el;
}

/* =================================================================
 * 5b. FOLDER MANAGEMENT + PINS (1.8.0) — same as Sealpost on your PC
 * ================================================================= */
const isSpecial = f => !!f.specialUse || f.path.toUpperCase() === 'INBOX';
/** Readable full path ("Projekte/Größe"): what pins are saved as, on every device. */
const upath = f => f.upath || f.path;
const delimOf = accId => ((state.folders[accId] || []).find(f => f.delimiter) || {}).delimiter || '/';

function folderMenuItems(a, f) {
  const pinned = (a.pinnedFolders || []).includes(upath(f));
  const items = [];
  if (!f.noselect) items.push({ label: '✓ Mark all as read', run: () => markFolderRead(a.id, f.path) }, '-');
  items.push({ label: pinned ? '📌 Unpin from top' : '📌 Pin to top', run: () => togglePin(a.id, upath(f)) });
  items.push({ label: '＋ New subfolder…', run: () => newFolderDialog(a.id, f.path) });
  if (!isSpecial(f)) {
    items.push({ label: '✎ Rename…', run: () => renameFolderDialog(a.id, f) });
    items.push({ label: '↳ Move folder to…', run: () => moveFolderDialog(a.id, f) });
    items.push('-', { label: '🗑 Delete folder…', run: () => deleteFolderDialog(a.id, f) });
  }
  return items;
}

/** Save pins / conversation view in the vault (syncs to your PCs). */
async function saveAccountPrefs(accId, patch) {
  const a = account(accId);
  if (!a) return;
  await saveToVault([{ id: 'account:' + accId, type: 'account', data: { ...a, ...patch } }]);
}

async function togglePin(accId, path) {
  const a = account(accId);
  const list = (a && a.pinnedFolders) || [];
  try { await saveAccountPrefs(accId, { pinnedFolders: list.includes(path) ? list.filter(p => p !== path) : [...list, path] }); renderTree(); }
  catch (e) { toast(e.message, 'err'); }
}

async function setConversation(accId, on) {
  try { await saveAccountPrefs(accId, { conversationView: on }); }
  catch (e) { return toast(e.message, 'err'); }
  state.expanded.clear();
  renderTree(); renderList(); updateConvButton();
  toast(`Conversation view ${on ? 'on' : 'off'} for ${(account(accId) || {}).email || 'this account'}.`);
}

/** Pins that point into a renamed / deleted folder follow it. */
async function fixPins(accId, from, to) {   // from / to: readable paths
  const a = account(accId), d = delimOf(accId);
  if (!a || !(a.pinnedFolders || []).length) return;
  const next = [];
  for (const p of a.pinnedFolders) {
    if (p === from || p.startsWith(from + d)) { if (to != null) next.push(to + p.slice(from.length)); }
    else next.push(p);
  }
  if (next.join('\n') !== a.pinnedFolders.join('\n')) await saveAccountPrefs(accId, { pinnedFolders: next });
}

function askFolderName(title, intro, value, accId) {
  const d = delimOf(accId);
  return dialog({
    title, okText: 'Save',
    html: `<p class="small">${intro}</p><input type="text" id="fnName" value="${esc(value || '')}" spellcheck="false" autocapitalize="off"><p id="fnErr" class="error"></p>`,
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
  try { await boxCall(accId, 'createFolder', { parent: parent || '', name }); await loadFolders(accId); toast(`Folder "${name}" created.`); }
  catch (e) { toast(e.message, 'err'); }
}

function followPath(accId, from, to) {
  const d = delimOf(accId);
  if (state.cur.accId === accId && (state.cur.folder === from || state.cur.folder.startsWith(from + d))) {
    selectFolder(accId, to == null ? 'INBOX' : to + state.cur.folder.slice(from.length));
  }
}

/** Rename and/or move: parent = server path of the new parent ('' = top level), name = plain text. */
async function doRename(accId, f, parent, name, done) {
  const d = delimOf(accId);
  try {
    const r = await boxCall(accId, 'renameFolder', { from: f.path, parent, name });
    const pf = parent && (state.folders[accId] || []).find(x => x.path === parent);
    await fixPins(accId, upath(f), (pf ? upath(pf) + d : '') + name);
    followPath(accId, f.path, r.path);
    await loadFolders(accId);
    toast(done);
  } catch (e) { toast(e.message, 'err'); }
}
const leafOf = (accId, f) => String(f.name).split(delimOf(accId)).pop();
const parentOf = (accId, f) => { const d = delimOf(accId), i = f.path.lastIndexOf(d); return i > 0 ? f.path.slice(0, i) : ''; };

async function renameFolderDialog(accId, f) {
  const leaf = leafOf(accId, f);
  const name = await askFolderName('Rename folder', `New name for <b>${esc(f.name)}</b>:`, leaf, accId);
  if (!name || name === leaf) return;
  await doRename(accId, f, parentOf(accId, f), name, `Renamed to "${name}".`);
}

async function moveFolderDialog(accId, f) {
  const d = delimOf(accId), leaf = leafOf(accId, f);
  const options = (state.folders[accId] || []).filter(x => x.path !== f.path && !x.path.startsWith(f.path + d));
  const r = await dialog({
    title: 'Move folder', okText: 'Move',
    html: `<p class="small">Move <b>${esc(f.name)}</b> (and its subfolders) into:</p>
      <select id="mvParent"><option value="">— Top level —</option>${options.map(x => `<option value="${esc(x.path)}">${' '.repeat((x.depth || 0) * 3)}${esc(x.name)}</option>`).join('')}</select>`,
    onOk: () => ({ parent: $('#mvParent').value })
  });
  if (!r || r.parent === parentOf(accId, f)) return;
  await doRename(accId, f, r.parent, leaf, `Moved "${leaf}".`);
}

async function deleteFolderDialog(accId, f) {
  const d = delimOf(accId);
  const subs = (state.folders[accId] || []).filter(x => x.path.startsWith(f.path + d));
  const n = (f.total || 0) + subs.reduce((t, x) => t + (x.total || 0), 0);
  if (!(await confirmBox('Delete folder', `Delete "${f.name}"${subs.length ? ` and its ${subs.length} subfolder${subs.length === 1 ? '' : 's'}` : ''}${n ? ` — including ${n} message${n === 1 ? '' : 's'}` : ''}? This deletes ${n ? 'them' : 'it'} on the mail server and can't be undone.`, 'Delete', true))) return;
  try {
    for (const x of subs.sort((p, q) => q.path.length - p.path.length)) await boxCall(accId, 'deleteFolder', { folder: x.path });
    await boxCall(accId, 'deleteFolder', { folder: f.path });
    await fixPins(accId, upath(f), null);
    followPath(accId, f.path, null);
    await loadFolders(accId);
    toast(`Deleted "${f.name}".`);
  } catch (e) { toast(e.message, 'err'); loadFolders(accId); }
}

function selectFolder(accId, folder) {
  Object.assign(state.cur, { accId, folder, page: 0, search: '' });
  $('#searchBox').value = '';
  clearSelection(false);
  const f = curFolderInfo();
  $('#folderTitle').textContent = accId === UNIFIED ? 'All Inboxes' : f ? f.name : (folder === 'INBOX' ? 'Inbox' : folder);
  state.messages = []; state.expanded.clear();   // 1.8.0
  updateConvButton();
  renderTree();
  closeReader();
  loadMessages();
}

/* =================================================================
 * 6. MESSAGE LIST
 * ================================================================= */
/** 1.8.0: All Inboxes — every account's Inbox, newest first, one page at a time. */
async function listAllInboxes() {
  const size = Number(state.vault.settings.pageSize) || 50, page = state.cur.page;
  const errors = [];
  let total = 0, more = false;
  const lists = await Promise.all(state.vault.accounts.map(async a => {
    try {
      const r = await boxCall(a.id, 'list', { folder: 'INBOX', page: 0, pageSize: Math.min(200, (page + 1) * size), search: state.cur.search });
      total += r.total || 0; more = more || r.hasMore;
      return r.messages.map(m => ({ ...m, accId: a.id, folder: 'INBOX', realUid: m.uid, uid: a.id + ':' + m.uid }));
    } catch (e) { errors.push(a.email + ': ' + e.message); return []; }
  }));
  const all = lists.flat().sort((x, y) => new Date(y.date) - new Date(x.date));
  return { messages: all.slice(page * size, (page + 1) * size), total, hasMore: more || all.length > (page + 1) * size, errors };
}

async function loadMessages({ append = false, quiet = false } = {}) {
  const token = ++state.listToken;
  if (!append && !quiet) {
    $('#messageList').innerHTML = '<div class="skeleton"></div>'.repeat(8);
    show($('#btnMore'), false);
  }
  try {
    const r = isUnified() ? await listAllInboxes() : await mailCall('list', { folder: state.cur.folder, page: state.cur.page, pageSize: Number(state.vault.settings.pageSize) || 50, search: state.cur.search });
    if (token !== state.listToken) return;
    if (r.errors && r.errors.length && !quiet) toast(r.errors.join(' · '), 'err');
    // keep subjects already decrypted in this tab
    const known = new Map(state.messages.map(m => [m.uid, m.subject]));
    for (const m of r.messages) if (m.encrypted && known.has(m.uid)) m.subject = known.get(m.uid);
    state.messages = append ? [...state.messages, ...r.messages] : r.messages;
    for (const uid of [...state.selected]) if (!state.messages.some(m => m.uid === uid)) state.selected.delete(uid);
    state.total = r.total;
    state.hasMore = r.hasMore;
    renderList();
  } catch (e) {
    if (token !== state.listToken) return;
    if (!quiet) $('#messageList').innerHTML = `<div class="list-empty">Couldn't load this folder.<br><span class="small">${esc(e.message)}</span></div>`;
  }
}

/* ---------- 1.8.0: conversations (same rules as Sealpost on your PC) ---------- */
const convOn = accId => !!(account(accId) || {}).conversationView;
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
    if (subj.length > 3 && !m.encrypted) {
      const k = acc + subj;
      if (!bySubject.has(k)) bySubject.set(k, []);
      bySubject.get(k).push({ me, reply: REPLY_RE.test(m.subject || '') });
    }
  }
  for (const g of bySubject.values()) if (g.length > 1 && g.some(x => x.reply)) for (const x of g.slice(1)) union(g[0].me, x.me);
  const out = new Map();
  for (const m of msgs) out.set(m.uid, find('m:' + m.uid));
  return out;
}
function listRows() {
  const conv = !isUnified() && isDraftsFolder() ? [] : state.messages.filter(m => convOn(m.accId || state.cur.accId));
  if (!conv.length) return state.messages.map(m => ({ kind: 'msg', m }));
  const keyOf = threadKeys(conv), groups = new Map();
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
function updateConvButton() {
  const b = $('#btnConv');
  if (!b) return;
  const id = state.cur.accId;
  show(b, !!id && id !== UNIFIED);
  const on = !!id && id !== UNIFIED && convOn(id);
  b.classList.toggle('on', on);
  b.title = on ? 'Conversation view is on for this account — click to turn it off' : 'Group replies into conversations (this account)';
}
let dragInfo = null;   // messages being dragged onto a folder
state.rows = [];

function renderList() {
  const list = $('#messageList');
  $('#folderCount').textContent = state.total ? `(${state.total})` : '';
  if (!state.messages.length) {
    list.innerHTML = `<div class="list-empty">${state.cur.search ? 'Nothing found.' : 'No messages here.'}</div>`;
    show($('#btnMore'), false);
    state.rows = []; state.visible = [];
    renderBulkBar();
    return;
  }
  const sentLike = !isUnified() && (/\\(Sent|Drafts)/.test((curFolderInfo() || {}).specialUse || '') || isDraftsFolder());
  const rows = listRows();
  state.rows = rows;
  state.visible = rows.filter(r => r.kind !== 'thread').map(r => r.m.uid);
  list.innerHTML = rows.map((row, i) => {
    const { m } = row;
    const t = row.kind === 'thread' ? row.msgs : null;
    const keys = t ? t.map(x => x.uid) : [m.uid];
    const unread = t ? t.some(x => !x.seen) : !m.seen;
    const allSel = keys.every(k => state.selected.has(k));
    const any = f => (t ? t.some(f) : f(m));
    let who = sentLike ? 'To: ' + (m.to || []).map(addrShort).join(', ') : (m.from || []).map(addrShort).join(', ');
    if (t) { const names = [...new Set(t.slice().reverse().map(x => addrShort((x.from || [])[0]) || '?'))]; who = names.slice(0, 3).join(', ') + (names.length > 3 ? ` +${names.length - 3}` : ''); }
    const open = t && state.expanded.has(row.key);
    const active = t ? keys.includes(state.selectedUid) && !open : m.uid === state.selectedUid;
    const acct = isUnified() ? (account(m.accId) || {}).email : '';
    const badges = (any(x => x.encrypted) ? '<span class="badge enc">🔒 PGP</span>' : '') + (any(x => x.signed) ? '<span class="badge sig">✍ Signed</span>' : '') + (any(x => x.attachment) ? '<span class="badge plain">📎</span>' : '');
    return `<div class="msg${unread ? ' unread' : ''}${active ? ' active' : ''}${allSel ? ' selected' : ''}${row.kind === 'child' ? ' child' : ''}${t ? ' thread' + (open ? ' open' : '') : ''}" data-uid="${esc(m.uid)}" data-row="${i}" role="button" tabindex="-1" draggable="true">
      <input type="checkbox" class="sel-box" aria-label="Select"${allSel ? ' checked' : ''}>
      <button class="read-dot" title="${unread ? 'Mark as read' : 'Mark as unread'}" aria-label="${unread ? 'Mark as read' : 'Mark as unread'}"></button>
      <div class="top"><span class="from">${t ? `<span class="tw">${open ? '▾' : '▸'}</span>` : ''}${esc(who || '(unknown)')}${t ? ` <span class="tcount">${t.length}</span>` : ''}</span>${any(x => x.answered) ? '<span class="muted" title="Answered">↩</span>' : ''}${any(x => x.flagged) ? '<span class="flag" title="Flagged">⚑</span>' : ''}<span class="date">${esc(fmtDate(m.date))}</span></div>
      <div class="subj">${esc(m.subject || '(no subject)')}<span class="badges">${badges}</span></div>${acct ? `<div class="acct-tag">${esc(acct)}</div>` : ''}</div>`;
  }).join('');
  show($('#btnMore'), state.hasMore);
  renderBulkBar();
}
const rowOf = el => state.rows[Number(el.dataset.row)];
const keysOfRow = row => (row.kind === 'thread' ? row.msgs.map(x => x.uid) : [row.m.uid]);

$('#messageList').addEventListener('dragstart', e => {
  const el = e.target.closest('.msg'); if (!el) return;
  const keys = keysOfRow(rowOf(el));
  const ks = keys.some(k => state.selected.has(k)) ? [...state.selected] : keys;
  dragInfo = { keys: ks, accIds: accountsOf(ks), folder: isUnified() ? 'INBOX' : state.cur.folder };
  e.dataTransfer.effectAllowed = 'move';
  e.dataTransfer.setData('text/plain', `${ks.length} message${ks.length === 1 ? '' : 's'}`);
});
$('#messageList').addEventListener('dragend', () => { dragInfo = null; $$('.folder.drop').forEach(x => x.classList.remove('drop')); });

/** Move messages (Move list, or dragged onto a folder). */
async function moveMessages(keys, accId, to) {
  keys = [].concat(keys);
  if (!keys.length) return;
  try {
    await perBox(keys, (a, f, u) => (a === accId && f !== to ? boxCall(a, 'move', { folder: f, to, uids: u }) : null));
    removeMany(keys);
    toast(`${keys.length} moved to ${((state.folders[accId] || []).find(f => f.path === to) || {}).name || to}.`);
  } catch (err) { toast(err.message, 'err'); }
}

$('#btnConv').addEventListener('click', () => { if (state.cur.accId && !isUnified()) setConversation(state.cur.accId, !convOn(state.cur.accId)); });

$('#messageList').addEventListener('click', e => {
  const el = e.target.closest('.msg');
  if (!el) return;
  const row = rowOf(el);
  if (!row) return;
  const uid = row.m.uid, keys = keysOfRow(row);
  const unread = row.kind === 'thread' ? row.msgs.some(x => !x.seen) : !row.m.seen;
  if (e.target.closest('.read-dot')) {   // 1.3.0: the dot toggles read / unread (a whole conversation at once)
    setSeen(keys, unread);
    return;
  }
  // 1.4.0: tick box, Ctrl-click and Shift-click select instead of opening
  if (e.target.closest('.sel-box') || e.ctrlKey || e.metaKey || e.shiftKey || state.selectMode || state.selected.size) {
    if (row.kind === 'thread') { const on = !keys.every(k => state.selected.has(k)); for (const k of keys) on ? state.selected.add(k) : state.selected.delete(k); renderList(); return; }
    if (e.shiftKey && state.anchor != null) selectRange(state.anchor, uid);
    else toggleSelect(uid);
    return;
  }
  if (row.kind === 'thread') {   // 1.8.0: conversation line — open it up, show the newest message
    if (state.expanded.has(row.key)) state.expanded.delete(row.key); else state.expanded.add(row.key);
    state.anchor = uid;
    if (state.expanded.has(row.key)) openMessage(uid); else renderList();
    return;
  }
  state.anchor = uid;
  if (!isUnified() && isDraftsFolder()) composer.openDraft(uid);   // drafts reopen in the composer
  else openMessage(uid);
});
$('#btnMore').addEventListener('click', () => { state.cur.page++; loadMessages({ append: true }); });
$('#btnRefresh').addEventListener('click', () => { state.cur.page = 0; loadMessages(); loadFolders(state.cur.accId); refreshVault(); });

let searchTimer = null;
$('#searchBox').addEventListener('input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => { state.cur.search = $('#searchBox').value.trim(); state.cur.page = 0; closeReader(); loadMessages(); }, 450);
});

/* =================================================================
 * 7. READER
 * ================================================================= */
function closeReader() {
  state.selectedUid = null;
  state.view = null;
  show($('#reader'), false);
  show($('#readerEmpty'), true);
  $('#app').classList.remove('reading');
  $$('.msg.active').forEach(e => e.classList.remove('active'));
}

async function openMessage(uid, { reparse = false } = {}) {
  state.selectedUid = uid;
  renderList();   // 1.8.0: highlights the right line (conversations too)
  show($('#readerEmpty'), false);
  show($('#reader'), true);
  $('#app').classList.add('reading');
  if (!reparse) {
    $('#rSubject').textContent = 'Loading…';
    $('#rFrom').textContent = $('#rTo').textContent = $('#rCc').textContent = $('#rDate').textContent = '';
    $('#textBody').textContent = '';
    $('#pgpBanner').innerHTML = '';
    $('#attachments').innerHTML = '';
    show($('#bodyToggle'), false);
    resetFrame('');
  }
  const key = msgKey(uid);
  try {
    let bytes = state.raw.get(key);
    if (!bytes) {
      const l = loc(uid);   // 1.8.0: the message's own account + folder
      const r = await boxCall(l.accId, 'message', { folder: l.folder, uid: l.uid, markSeen: true }, { raw: true });
      bytes = r.bytes;
      state.raw.set(key, bytes);
      if (state.raw.size > 15) state.raw.delete(state.raw.keys().next().value);
    }
    if (state.selectedUid !== uid) return;
    const v = await readMessage(bytes, keyring);
    if (state.selectedUid !== uid) return;
    const where = loc(uid);
    v.key = key; v.uid = where.uid; v.folder = where.folder; v.accId = where.accId;
    v.sender = senderCheck(v);
    state.view = v;
    const m = state.messages.find(x => x.uid === uid);
    if (m && v.pgp.protectedSubject && v.subject && m.subject !== v.subject) { m.subject = v.subject; renderList(); } // real (encrypted) subject in the list
    if (m && !m.seen) { m.seen = true; renderList(); bumpUnread(-1, where.accId, where.folder); }
    renderMessage(v);
  } catch (e) {
    if (state.selectedUid !== uid) return;
    $('#rSubject').textContent = 'Could not open this message';
    $('#textBody').textContent = e.message;
    show($('#textBody'), true);
  }
}

function bumpUnread(delta, accId = state.cur.accId, folder = state.cur.folder) {
  const f = (state.folders[accId] || []).find(x => x.path === folder);
  if (f) { f.unseen = Math.max(0, (f.unseen || 0) + delta); renderTree(); }
}

function renderMessage(v) {
  $('#rSubject').textContent = v.subject || '(no subject)';
  $('#rFrom').textContent = v.from.map(addr).join(', ');
  $('#rTo').textContent = v.to.map(addr).join(', ') || '—';
  $('#rCc').textContent = v.cc.map(addr).join(', ');
  show($('#rCcRow'), v.cc.length > 0);
  $('#rDate').textContent = fmtDate(v.date, true);
  const m = state.messages.find(x => x.uid === state.selectedUid);
  $('[data-act=flag]').classList.toggle('on', !!(m && m.flagged));
  $('#pFlag').classList.toggle('on', !!(m && m.flagged));   // 1.9.0 phone toolbar
  updateReadButton(); // 1.3.0
  const from = (v.from[0] && v.from[0].address) || '';
  show($('[data-act=addContact]'), !!from && !state.vault.contacts.some(c => (c.emails || []).includes(from)));
  renderMoveSelect();
  renderPgpBanner(v);
  renderAttachments(v);
  renderBody(v, v.html ? 'html' : 'text');
}

/* ---------- 7a. Is the signer the key assigned to this contact? ---------- */
function senderCheck(v) {
  const from = (v.from[0] && v.from[0].address) || '';
  const contact = state.vault.contacts.find(c => (c.emails || []).includes(from));
  if (!contact || !contact.keyFp) return contact ? { contact, status: 'contact' } : null;
  const pinned = keyring.publicKeys.get(contact.keyFp);
  const ids = pinned ? pinned.getKeys().map(k => k.getKeyID().toHex().toUpperCase()) : [];
  const sig = v.pgp.signatures[0];
  if (sig && !ids.includes(sig.keyId) && sig.fingerprint !== contact.keyFp) return { contact, status: 'key-changed', changedTo: sig.fingerprint || sig.keyId, changedFp: sig.fingerprint };
  return { contact, status: 'ok' };
}

/* ---------- 7b. PGP status banners ---------- */
function renderPgpBanner(v) {
  const p = v.pgp;
  const box = $('#pgpBanner');
  box.innerHTML = '';
  const add = (kind, ico, html) => {
    const d = document.createElement('div');
    d.className = 'pgp-banner ' + kind;
    d.innerHTML = `<span class="ico" aria-hidden="true">${ico}</span><div class="msg-txt">${html}</div>`;
    box.appendChild(d);
    return d;
  };
  const button = (box, label, fn, cls = 'btn small') => { const b = document.createElement('button'); b.className = cls; b.textContent = label; b.onclick = async () => { try { await fn(); } catch (e) { if (e.code !== 'CANCELLED') toast(e.message, 'err'); } }; box.appendChild(b); };

  if (p.needPassphrase) {
    const d = add('info', '🔒', `<b>Encrypted message.</b> Unlock your key to read it.<div class="sub">${esc(p.needPassphrase.userId || '')}</div>`);
    button(d, 'Unlock & decrypt', async () => {
      if (await promptPassphrase(keyring, p.needPassphrase.fingerprint, p.needPassphrase.userId)) openMessage(state.selectedUid, { reparse: true });
    }, 'btn primary small');
  } else if (p.encrypted && p.decrypted) {
    add('ok', '🔒', `<b>Decrypted in this browser.</b> This message was end-to-end encrypted${p.inline ? ' (inline PGP)' : ''}.${p.protectedSubject ? ' The subject was protected too.' : ''}`);
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
      continue; // explained by the key-change warning below
    } else if (s.unknownKey) {
      const d = add('warn', '?', `<b>Signed with a key you don't have</b> (ID ${esc(s.keyId)}). The signature can't be checked yet.`);
      const keyAtt = v.attachments.find(a => a.isKey);
      if (v.autocryptKey || keyAtt) button(d, 'Import sender’s key', () => importOfferedKey(v));
    } else {
      add('bad', '✖', `<b>BAD SIGNATURE.</b> The message was altered or the signature is forged.<div class="sub">${esc(s.signer || s.keyId)} — ${esc(s.error || '')}</div>`);
    }
  }
  if (p.signed && !p.signatures.length && !p.needPassphrase && p.decrypted !== false) {
    add('warn', '⚠', '<b>Signature present but could not be checked.</b>' + (p.errors.length ? `<div class="sub">${esc(p.errors.join(' · '))}</div>` : ''));
  }
  for (const n of p.notes) add('warn', 'ℹ', esc(n));

  const s = v.sender;
  if (s && s.status === 'key-changed') {
    const d = add('bad', '⚠', `<b>Key change for ${esc(s.contact.name || s.contact.emails[0])}.</b> This message was signed with a different key than the one assigned to this contact.
      That can mean they made a new key — or that someone is impersonating them. Confirm with them before switching.
      <div class="sub">Assigned: ${esc(s.contact.keyFp)}<br>This message: ${esc(s.changedTo || '')}</div>`);
    if (s.changedFp && keyring.publicKeys.has(s.changedFp)) button(d, 'Use new key…', async () => {
      if (!(await confirmBox('Switch key', `Assign the new key to ${s.contact.name || s.contact.emails[0]}? Only do this if you have confirmed it with them.`, 'Use new key', true))) return;
      await ctx.save([{ id: 'contact:' + s.contact.id, type: 'contact', data: { ...s.contact, keyFp: s.changedFp, updated: new Date().toISOString() } }]);
      toast('Contact updated.');
    }, 'btn small danger');
  } else if (v.autocryptKey && !(s && s.status === 'ok')) {
    const d = add('info', '🔑', 'The sender included their public key (Autocrypt).');
    button(d, 'Import key', () => importOfferedKey(v));
  }
}

/** Import the key a message offers (Autocrypt header or attached .asc) and assign it to the sender's contact. */
async function importOfferedKey(v, attachment = null) {
  let text;
  if (attachment) text = new TextDecoder().decode(attachment.bytes);
  else if (v.autocryptKey) {
    const bin = atob(v.autocryptKey); const b = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
    text = b;
  } else { const a = v.attachments.find(x => x.isKey); text = a ? new TextDecoder().decode(a.bytes) : null; }
  if (!text) return;
  const r = await people.importKeys(text, { from: (v.from[0] && v.from[0].address) || '', name: (v.from[0] && v.from[0].name) || '' });
  if (r) { v.sender = senderCheck(v); openMessage(state.selectedUid, { reparse: true }); }
}

/* ---------- 7c. Attachments ---------- */
function renderAttachments(v) {
  const box = $('#attachments');
  box.innerHTML = '';
  for (const a of v.attachments.filter(a => !a.inline || !v.html)) {
    const el = document.createElement('div');
    el.className = 'att';
    el.innerHTML = `<span aria-hidden="true">${a.isKey ? '🔑' : a.isEncrypted ? '🔒' : '📄'}</span><span class="att-name" title="${esc(a.filename)}">${esc(a.filename)}</span><span class="att-size">${fmtSize(a.size)}</span>`;
    const btn = (label, fn) => { const b = document.createElement('button'); b.className = 'btn small'; b.textContent = label; b.onclick = async () => { try { await fn(); } catch (e) { if (e.code !== 'CANCELLED') toast(e.message, 'err'); } }; el.appendChild(b); };
    if (a.isKey) btn('Import key', () => importOfferedKey(v, a));
    if (a.isEncrypted) btn('Decrypt & download', async () => {
      const r = await withPassphrase(keyring, () => keyring.decrypt(a.bytes));
      download(r.data, a.filename.replace(/\.(pgp|gpg|asc)$/i, '') || 'decrypted');
      toast('Decrypted in this browser and downloaded.');
    });
    btn('Download', () => download(a.bytes, a.filename, a.contentType));
    box.appendChild(el);
  }
}

/* ---------- 7d. Body: sandboxed HTML or plain text ---------- */
function resetFrame(doc) {
  // a brand-new frame each time: no scripts, no access to this page, its own strict policy
  const f = document.createElement('iframe');
  f.id = 'htmlBody';
  f.title = 'Message body';
  f.setAttribute('sandbox', 'allow-popups allow-popups-to-escape-sandbox');
  f.setAttribute('referrerpolicy', 'no-referrer');
  f.srcdoc = doc;
  if (!doc) f.classList.add('hidden');
  $('#htmlBody').replaceWith(f);
}

function renderBody(v, mode) {
  const hasHtml = !!v.html;
  show($('#bodyToggle'), hasHtml);
  $$('#bodyToggle button').forEach(b => b.classList.toggle('on', b.dataset.mode === mode));
  if (mode === 'html' && hasHtml) {
    const allowRemote = !!state.vault.settings.loadRemoteImages || state.remoteAllowedFor === v.key;
    const hasRemote = /<img[^>]+src=["']?https?:|url\(["']?https?:/i.test(v.html);
    show($('#remoteBar'), hasRemote && !allowRemote);
    const csp = `default-src 'none'; style-src 'unsafe-inline'; font-src data:; img-src data: ${allowRemote ? 'https: http:' : ''};`;
    const doc = `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="${csp}">` +
      `<meta name="referrer" content="no-referrer"><base target="_blank">` +
      `<style>body{font-family:Segoe UI,system-ui,-apple-system,sans-serif;font-size:14px;color:#111;margin:14px;word-wrap:break-word}img{max-width:100%;height:auto}</style></head><body>` +
      v.html + '</body></html>';
    show($('#textBody'), false);
    resetFrame(doc);
  } else {
    show($('#remoteBar'), false);
    resetFrame('');
    show($('#textBody'), true);
    const t = $('#textBody');
    t.innerHTML = '';
    for (const line of (v.text || '').replace(/\r\n?/g, '\n').split('\n')) {
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
    a.href = m[0]; a.textContent = m[0]; a.target = '_blank'; a.rel = 'noopener noreferrer';
    parent.appendChild(a);
    last = m.index + m[0].length;
  }
  parent.appendChild(document.createTextNode(text.slice(last)));
}

$$('#bodyToggle button').forEach(b => b.addEventListener('click', () => state.view && renderBody(state.view, b.dataset.mode)));
$('#btnLoadImages').addEventListener('click', () => { state.remoteAllowedFor = state.view.key; renderBody(state.view, 'html'); });

/* =================================================================
 * 8. READER ACTIONS
 * ================================================================= */
function renderMoveSelect() {
  const sel = $('#moveSelect');
  sel.innerHTML = '<option value="">Move to…</option>';
  const l = state.selectedUid != null ? loc(state.selectedUid) : { accId: state.cur.accId, folder: state.cur.folder };
  for (const f of state.folders[l.accId] || []) {
    if (f.path === l.folder || f.noselect) continue;
    const o = document.createElement('option');
    o.value = f.path; o.textContent = ' '.repeat((f.depth || 0) * 3) + f.name;
    sel.appendChild(o);
  }
}

$('#moveSelect').addEventListener('change', async e => {
  const target = e.target.value;
  e.target.value = '';
  if (!target || !state.selectedUid) return;
  try {
    const l = loc(state.selectedUid);
    await boxCall(l.accId, 'move', { folder: l.folder, to: target, uids: [l.uid] });
    const name = ((state.folders[l.accId] || []).find(f => f.path === target) || {}).name || target;
    removeFromList(state.selectedUid);
    toast('Moved to ' + name);
  } catch (err) { toast(err.message, 'err'); }
});

function removeFromList(uid) {
  const acc = loc(uid).accId;
  state.raw.delete(msgKey(uid));
  const order = state.visible && state.visible.length ? state.visible : state.messages.map(m => m.uid);
  const i = order.indexOf(uid);
  state.messages = state.messages.filter(m => m.uid !== uid);
  state.total = Math.max(0, state.total - 1);
  renderList();
  const narrow = matchMedia('(max-width: 860px)').matches;
  const next = [order[i + 1], order[i - 1]].find(k => k != null && state.messages.some(m => m.uid === k));
  if (next != null && !narrow) openMessage(next); else closeReader();
  loadFolders(acc);
}

async function deleteSelected() {
  if (!state.selectedUid) return;
  const f = curFolderInfo();
  if (f && f.specialUse === '\\Trash' && !(await confirmBox('Delete for good', 'This message is in Trash. Delete it permanently?', 'Delete', true))) return;
  try {
    const l = loc(state.selectedUid);
    const r = await boxCall(l.accId, 'delete', { folder: l.folder, uids: [l.uid] });
    removeFromList(state.selectedUid);
    toast(r.result === 'trash' ? 'Moved to Trash' : 'Deleted');
  } catch (e) { toast(e.message, 'err'); }
}

$$('.reader-actions [data-act]').forEach(b => b.addEventListener('click', async () => {
  const act = b.dataset.act, v = state.view;
  if (!v) return;
  const m = state.messages.find(x => x.uid === state.selectedUid);
  try {
    if (act === 'reply' || act === 'replyAll' || act === 'forward') return composer.openComposer({ mode: act, view: v });
    if (act === 'delete') return deleteSelected();
    if (act === 'addContact') {
      const from = v.from[0];
      await people.addContact({ name: from.name || '', email: from.address });
      renderMessage(v);
      return;
    }
    if (act === 'flag') {
      const on = !(m && m.flagged);
      const l = loc(state.selectedUid);
      await boxCall(l.accId, 'flag', { folder: l.folder, uids: [l.uid], flag: 'flagged', on });
      if (m) m.flagged = on;
      b.classList.toggle('on', on);
      renderList();
    }
    if (act === 'unread') {   // 1.3.0: toggles read / unread
      const on = !(m ? m.seen : true);
      await setSeen([state.selectedUid], on);
      toast(on ? 'Marked as read' : 'Marked as unread');
    }
    if (act === 'source') {
      const raw = new TextDecoder('utf-8').decode(state.raw.get(v.key) || new Uint8Array());
      dialog({ title: 'Message source', html: `<textarea readonly style="width:100%">${esc(raw)}</textarea>`, hideCancel: true, okText: 'Close', wide: true });
    }
  } catch (e) { if (e.code !== 'CANCELLED') toast(e.message, 'err'); }
}));

/* =================================================================
 * 8b. READ / UNREAD, MARK FOLDER READ, RIGHT-CLICK MENUS (1.3.0)
 * ================================================================= */
/** Mark messages in the open folder read (on=true) or unread. */
async function setSeen(uids, on) {
  try {
    await perBox(uids, (a, f, u) => boxCall(a, 'flag', { folder: f, uids: u, flag: 'seen', on }));   // 1.8.0: per account
    for (const m of state.messages) if (uids.includes(m.uid) && m.seen !== on) {
      m.seen = on;
      bumpUnread(on ? -1 : 1, m.accId || state.cur.accId, m.folder || state.cur.folder);
    }
    renderList();
    updateReadButton();
  } catch (e) { toast(e.message, 'err'); }
}

/** Every unread message in a folder becomes read. */
async function markFolderRead(accId, folder) {
  if (accId === UNIFIED) {   // 1.8.0: every Inbox
    let n = 0;
    for (const a of state.vault.accounts) {
      try { const r = await vault.mail('markAllRead', { account: vault.imapDetails(a), folder: 'INBOX' }); n += r.count || 0; } catch (e) { toast(a.email + ': ' + e.message, 'err'); }
      const f = (state.folders[a.id] || []).find(x => x.path.toUpperCase() === 'INBOX'); if (f) f.unseen = 0;
    }
    if (isUnified()) { for (const m of state.messages) m.seen = true; renderList(); updateReadButton(); }
    renderTree();
    return toast(n ? `Marked ${n} message${n === 1 ? '' : 's'} as read.` : 'Everything here is already read.');
  }
  try {
    const r = await vault.mail('markAllRead', { account: vault.imapDetails(account(accId)), folder });
    if (accId === state.cur.accId && folder === state.cur.folder) { for (const m of state.messages) m.seen = true; renderList(); updateReadButton(); }
    const f = (state.folders[accId] || []).find(x => x.path === folder);
    if (f) { f.unseen = 0; renderTree(); }
    toast(r.count ? `Marked ${r.count} message${r.count === 1 ? '' : 's'} as read.` : 'Everything here is already read.');
  } catch (e) { toast(e.message, 'err'); }
}
$('#btnMarkAllRead').addEventListener('click', () => state.cur.accId && markFolderRead(state.cur.accId, state.cur.folder));

/** The reader's read/unread button says what clicking it will do. */
function updateReadButton() {
  const b = $('[data-act=unread]');
  const m = state.messages.find(x => x.uid === state.selectedUid);
  const seen = !m || m.seen;
  b.textContent = seen ? 'Mark unread' : 'Mark read';
  b.title = (seen ? 'Mark unread' : 'Mark read') + ' (U)';
}

/* ---------- right-click menus ---------- */
function showMenu(e, items) {
  const menu = $('#ctxMenu');
  menu.innerHTML = '';
  for (const it of items) {
    if (it === '-') { const hr = document.createElement('div'); hr.className = 'ctx-sep'; menu.appendChild(hr); continue; }
    const b = document.createElement('button');
    b.className = 'ctx-item'; b.textContent = it.label; b.type = 'button';
    b.onclick = () => { hideMenu(); it.run(); };
    menu.appendChild(b);
  }
  show(menu, true);
  const w = menu.offsetWidth, h = menu.offsetHeight;
  menu.style.left = Math.max(4, Math.min(e.clientX, innerWidth - w - 8)) + 'px';
  menu.style.top = Math.max(4, Math.min(e.clientY, innerHeight - h - 8)) + 'px';
}
function hideMenu() { show($('#ctxMenu'), false); }
let menuGuardUntil = 0;   // 1.9.0: lifting the finger after press-and-hold must not close the menu it opened
document.addEventListener('mousedown', e => { if (Date.now() < menuGuardUntil) return; if (!e.target.closest('#ctxMenu')) hideMenu(); });
document.addEventListener('touchstart', e => { if (!e.target.closest('#ctxMenu')) hideMenu(); }, { passive: true });
document.addEventListener('keydown', e => { if (e.key === 'Escape') hideMenu(); }, true);
window.addEventListener('blur', hideMenu);
$('#messageList').addEventListener('scroll', hideMenu);

$('#messageList').addEventListener('contextmenu', e => {
  const row = e.target.closest('.msg');
  if (!row) return;
  e.preventDefault();
  openRowMenu(row, e);
});

/** Menu for one line of the list (right-click, or press and hold on a phone). */
function openRowMenu(row, e) {
  const r = rowOf(row);
  if (!r) return;
  const m = r.m;
  if (r.kind === 'thread') {   // 1.8.0: a whole conversation
    const keys = keysOfRow(r), unread = r.msgs.some(x => !x.seen);
    return showMenu(e, [
      { label: unread ? '○ Mark conversation as read' : '● Mark conversation as unread', run: () => setSeen(keys, unread) },
      { label: '☐ Select conversation', run: () => { keys.forEach(k => state.selected.add(k)); renderList(); } },
      { label: '🗑 Delete conversation', run: () => deleteKeys(keys) }
    ]);
  }
  showMenu(e, [
    { label: m.seen ? '● Mark as unread' : '○ Mark as read', run: () => setSeen([m.uid], !m.seen) },
    { label: m.flagged ? '⚑ Remove flag' : '⚑ Flag', run: async () => {
      try { await perBox([m.uid], (a, f, u) => boxCall(a, 'flag', { folder: f, uids: u, flag: 'flagged', on: !m.flagged })); m.flagged = !m.flagged; renderList(); if (m.uid === state.selectedUid) $('[data-act=flag]').classList.toggle('on', m.flagged); }
      catch (err) { toast(err.message, 'err'); }
    } },
    { label: '📁 Move to…', run: () => moveMenu(e, [m.uid]) },   // 1.9.0
    { label: '🗑 Delete', run: () => deleteKeys([m.uid]) },
    '-',
    { label: '✓ Mark all in this folder as read', run: () => markFolderRead(state.cur.accId, state.cur.folder) }
  ]);
}

/* =================================================================
 * 8c. SELECTING SEVERAL MESSAGES (1.4.0)
 *    Tick boxes (☐ button, or hover), Ctrl-click, Shift-click for a
 *    range, Ctrl+A for everything loaded. The bar above the list then
 *    works on all ticked messages at once.
 * ================================================================= */
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
function clearSelection(render = true) {
  state.selected.clear();
  state.selectMode = false;
  if (render) renderList(); else renderBulkBar();
}

function renderBulkBar() {
  const n = state.selected.size;
  const selecting = n > 0 || state.selectMode;
  $('#messageList').classList.toggle('selecting', selecting);
  $('#app').classList.toggle('selecting', selecting);   // 1.9.0: hides the ✎ button while selecting
  $('#btnSelectMode').classList.toggle('on', selecting);
  show($('#bulkBar'), selecting);
  $('#bulkCount').textContent = n ? `${n} selected` : 'Tick messages';
  $$('#bulkBar [data-bulk]').forEach(b => { if (!['all', 'clear'].includes(b.dataset.bulk)) b.disabled = !n; });
  const sel = $('#bulkMove');
  const accs = accountsOf([...state.selected]);   // 1.8.0: All Inboxes — one account at a time
  const moveAcc = isUnified() ? (accs.size === 1 ? [...accs][0] : null) : state.cur.accId;
  sel.disabled = !n || !moveAcc;
  sel.title = moveAcc ? '' : 'Select messages from one account to move them';
  sel.innerHTML = '<option value="">Move to…</option>' + (state.folders[moveAcc] || [])
    .filter(f => f.path !== (isUnified() ? 'INBOX' : state.cur.folder) && !f.noselect)
    .map(f => `<option value="${esc(f.path)}">${'\u00a0'.repeat((f.depth || 0) * 3)}${esc(f.name)}</option>`).join('');
}

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
      await perBox(uids, (a, f, u) => boxCall(a, 'flag', { folder: f, uids: u, flag: 'flagged', on }));
      for (const m of state.messages) if (uids.includes(m.uid)) m.flagged = on;
      renderList();
      toast(`${uids.length} ${on ? 'flagged' : 'unflagged'}.`);
    }
    if (act === 'delete') {
      const f = curFolderInfo();
      if (!(await confirmBox('Delete messages', f && f.specialUse === '\\Trash' ? `Delete ${uids.length} message(s) permanently?` : `Move ${uids.length} message(s) to Trash?`, 'Delete', true))) return;
      const rs = await perBox(uids, (a, f, u) => boxCall(a, 'delete', { folder: f, uids: u }));
      removeMany(uids);
      toast(`${uids.length} ${rs.every(r => r && r.result === 'trash') ? 'moved to Trash' : 'deleted'}.`);
    }
  } catch (e) { toast(e.message, 'err'); }
}));

$('#bulkMove').addEventListener('change', async e => {
  const to = e.target.value;
  e.target.value = '';
  const uids = [...state.selected];
  if (!to || !uids.length) return;
  const accs = [...accountsOf(uids)];
  if (accs.length === 1) moveMessages(uids, accs[0], to);
});

/** Take several messages out of the list (moved / deleted). */
function removeMany(uids) {
  const set = new Set(uids);
  const accs = accountsOf(uids);
  for (const u of uids) state.raw.delete(msgKey(u));
  state.messages = state.messages.filter(m => !set.has(m.uid));
  state.total = Math.max(0, state.total - uids.length);
  if (set.has(state.selectedUid)) closeReader();
  clearSelection();
  for (const a of accs) loadFolders(a);
}

/* =================================================================
 * 9. PHONE LAYOUT
 * ================================================================= */
function closeNav() { $('#app').classList.remove('nav-open'); }
$$('#btnNav, .nav-open-btn').forEach(b => b.addEventListener('click', () => $('#app').classList.add('nav-open')));
$('#btnCloseNav').addEventListener('click', closeNav);
$('#navShade').addEventListener('click', closeNav);
$('#btnBack').addEventListener('click', closeReader);

/* =================================================================
 * 10. BACKGROUND REFRESH + KEYBOARD
 * ================================================================= */
async function backgroundRefresh() {
  if (document.hidden || !state.vault || !state.cur.accId) return;
  loadFolders(state.cur.accId);
  if (state.screen === 'mail' && state.cur.page === 0 && !state.cur.search) {
    const before = new Set(state.messages.map(m => m.uid));
    await loadMessages({ quiet: true });
    const fresh = state.messages.filter(m => !before.has(m.uid) && !m.seen).length;
    if (fresh && before.size && !isDraftsFolder()) toast(fresh === 1 ? 'New message' : `${fresh} new messages`);
  }
}

/** Accounts, contacts, keys or settings changed on another device? */
async function refreshVault() {
  if (!state.vault) return;
  try {
    const sig = v => JSON.stringify(v.accounts.map(a => [a.id, a.email, a.imapHost, a.imapPort, a.username, a.password]));
    const before = sig(state.vault);
    state.vault = await vault.loadVault(state.vault);
    await reloadKeyring();
    if (sig(state.vault) !== before) loadAccounts();
    if (state.screen === 'contacts') people.showContacts();
    if (state.screen === 'keys') people.showKeys();
  } catch (e) { if (e.code !== 'not_signed_in') console.warn('Vault refresh failed', e.message); }
}
ctx.refreshVault = refreshVault;

document.addEventListener('visibilitychange', () => { if (!document.hidden && state.vault) backgroundRefresh(); });

document.addEventListener('keydown', e => {
  if (!state.vault || state.screen !== 'mail' || composer.isOpen() || e.target.closest('input,textarea,select,[contenteditable]') || !$('#dlgModal').classList.contains('hidden') || !$('#passModal').classList.contains('hidden')) return;
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'a' && state.messages.length) { e.preventDefault(); selectAll(); return; }   // 1.4.0
  if (e.key === 'Escape' && (state.selected.size || state.selectMode)) { clearSelection(); return; }
  if (e.key === 'Delete' && state.selected.size) { e.preventDefault(); $('#bulkBar [data-bulk=delete]').click(); return; }
  if (e.key === 'Delete' && state.selectedUid) { e.preventDefault(); deleteSelected(); }
  if (e.key === 'Escape' && state.selectedUid) closeReader();
  if (e.key === 'u' && state.selectedUid) { e.preventDefault(); const m = state.messages.find(x => x.uid === state.selectedUid); if (m) setSeen([m.uid], !m.seen); }   // 1.3.0
  if (e.key === 'r' && state.view) { e.preventDefault(); composer.openComposer({ mode: 'reply', view: state.view }); }
  if (e.key === 'n') { e.preventDefault(); composer.openComposer(); }
  if ((e.key === 'ArrowDown' || e.key === 'j' || e.key === 'ArrowUp' || e.key === 'k') && state.messages.length && (isUnified() || !isDraftsFolder())) {
    e.preventDefault();
    const order = state.visible && state.visible.length ? state.visible : state.messages.map(m => m.uid);   // 1.8.0: what the list shows
    const i = order.indexOf(state.selectedUid);
    const k = order[(e.key === 'ArrowDown' || e.key === 'j') ? Math.min(order.length - 1, i + 1) : Math.max(0, i - 1)];
    openMessage(k);
    const row = document.querySelector(`.msg[data-uid="${k}"]:not(.thread)`);
    if (row) row.scrollIntoView({ block: 'nearest' });
  }
});

window.addEventListener('beforeunload', e => { if (composer.isOpen() && composer.isDirty()) { e.preventDefault(); e.returnValue = ''; } });

/* =================================================================
 * 11. PHONE LAYOUT (1.9.0)
 *     - toolbar at the bottom when reading (Delete · Move · Flag · Reply)
 *     - Back + ⋯ at the top, ✎ New message bottom-right
 *     - press and hold a message for its menu
 *     - swipe a message left = delete, right = read / unread
 *     - pull the list down to refresh
 *     Menus open as a sheet at the bottom of the screen (style.css 18g).
 * ================================================================= */
const isPhone = () => matchMedia('(max-width: 860px)').matches;
const act = name => $(`.reader-actions [data-act=${name}]`).click();   // the (hidden) reader buttons do the work

/** Delete messages (swipe, menus); in Trash asks first, as everywhere else. */
async function deleteKeys(keys) {
  const f = curFolderInfo();
  if (!isUnified() && f && f.specialUse === '\\Trash' && !(await confirmBox('Delete for good', `Delete ${keys.length === 1 ? 'this message' : keys.length + ' messages'} permanently?`, 'Delete', true))) return renderList();
  try {
    const rs = await perBox(keys, (a, fo, u) => boxCall(a, 'delete', { folder: fo, uids: u }));
    removeMany(keys);
    toast(rs.every(r => r && r.result === 'trash') ? (keys.length === 1 ? 'Moved to Trash' : `${keys.length} moved to Trash`) : 'Deleted');
  } catch (e) { toast(e.message, 'err'); renderList(); }
}

/** Folder list as a menu (one account at a time). */
function moveMenu(e, keys) {
  const accs = [...accountsOf(keys)];
  if (accs.length !== 1) return toast('Select messages from one account to move them.', 'err');
  const from = loc(keys[0]).folder;
  const items = (state.folders[accs[0]] || []).filter(f => !f.noselect && f.path !== from)
    .map(f => ({ label: ' '.repeat((f.depth || 0) * 3) + (f.depth ? '' : '') + f.name, run: () => moveMessages(keys, accs[0], f.path) }));
  showMenu(e, items.length ? items : [{ label: 'No other folders', run: () => {} }]);
}

// --- reading: top bar + bottom toolbar ---
$('#pBack').addEventListener('click', closeReader);
$('#pMore').addEventListener('click', e => {
  const m = state.messages.find(x => x.uid === state.selectedUid);
  const v = state.view;
  if (!v) return;
  const items = [{ label: m && !m.seen ? '○ Mark as read' : '● Mark as unread', run: () => act('unread') }];
  if (!$('[data-act=addContact]').classList.contains('hidden')) items.push({ label: '👤 Add sender to contacts', run: () => act('addContact') });
  items.push({ label: '↪ Forward', run: () => act('forward') }, '-', { label: '</> View source', run: () => act('source') });
  showMenu(e, items);
});
$('#pDelete').addEventListener('click', () => act('delete'));
$('#pFlag').addEventListener('click', () => { act('flag'); setTimeout(() => { const m = state.messages.find(x => x.uid === state.selectedUid); $('#pFlag').classList.toggle('on', !!(m && m.flagged)); }, 600); });
$('#pMove').addEventListener('click', e => { if (state.selectedUid != null) moveMenu(e, [state.selectedUid]); });
$('#pReply').addEventListener('click', e => showMenu(e, [
  { label: '↩ Reply', run: () => act('reply') },
  { label: '↩↩ Reply all', run: () => act('replyAll') },
  { label: '↪ Forward', run: () => act('forward') }
]));

// --- list: ✎ and ⋯ ---
$('#btnFab').addEventListener('click', () => composer.openComposer());
$('#btnListMore').addEventListener('click', e => {
  const items = [
    { label: '☐ Select messages', run: () => $('#btnSelectMode').click() },
    { label: '✓ Mark all as read', run: () => $('#btnMarkAllRead').click() }
  ];
  if (state.cur.accId && !isUnified()) items.push({ label: (convOn(state.cur.accId) ? '☑' : '☐') + ' Conversation view (this account)', run: () => setConversation(state.cur.accId, !convOn(state.cur.accId)) });
  items.push('-', { label: '⟳ Refresh', run: () => $('#btnRefresh').click() });
  showMenu(e, items);
});
$('#cSendTop').addEventListener('click', () => $('#cSend').click());

// --- touch: press and hold, swipe, pull to refresh ---
(() => {
  const list = $('#messageList');
  const LONG_MS = 500, SWIPE_AT = 90;
  let t = null;                  // current touch: { x, y, row, mode, timer, dx, under }
  let suppressClick = false;

  const endSwipe = () => {
    if (!t || !t.row) return;
    t.row.classList.remove('swiping');
    t.row.classList.add('settle');
    t.row.style.transform = '';
    const row = t.row, under = t.under;
    setTimeout(() => { row.classList.remove('settle'); if (under) under.remove(); }, 220);
  };

  list.addEventListener('touchstart', e => {
    if (!isPhone() || e.touches.length !== 1) return;
    const p = e.touches[0];
    const row = e.target.closest('.msg');
    t = { x: p.clientX, y: p.clientY, row, mode: null, dx: 0, dy: 0, top: list.scrollTop <= 0 };
    if (row && !e.target.closest('.sel-box, .read-dot')) {
      t.timer = setTimeout(() => {          // press and hold -> the message's menu
        if (!t || t.mode) return;
        t.mode = 'long';
        suppressClick = true;
        menuGuardUntil = Date.now() + 900;
        openRowMenu(row, { clientX: t.x, clientY: t.y, preventDefault() {} });
      }, LONG_MS);
    }
  }, { passive: true });

  list.addEventListener('touchmove', e => {
    if (!t) return;
    const p = e.touches[0];
    t.dx = p.clientX - t.x; t.dy = p.clientY - t.y;
    if (!t.mode && (Math.abs(t.dx) > 10 || Math.abs(t.dy) > 10)) {
      clearTimeout(t.timer);
      if (t.row && Math.abs(t.dx) > Math.abs(t.dy) * 1.3 && !state.selectMode && !state.selected.size) {
        t.mode = 'swipe';
        t.row.classList.add('swiping');
        t.under = document.createElement('div');
        t.under.style.top = t.row.offsetTop + 'px';
        t.under.style.height = t.row.offsetHeight + 'px';
        list.insertBefore(t.under, t.row);
      } else if (t.top && t.dy > 0 && Math.abs(t.dy) > Math.abs(t.dx)) t.mode = 'pull';
      else t.mode = 'scroll';
    }
    if (t.mode === 'swipe') {
      const left = t.dx < 0;
      const r = rowOf(t.row);
      const unread = r && (r.kind === 'thread' ? r.msgs.some(x => !x.seen) : !r.m.seen);
      t.under.className = 'swipe-under ' + (left ? 'del' : 'read') + (Math.abs(t.dx) > SWIPE_AT ? ' armed' : '');
      t.under.textContent = left ? '🗑 Delete' : (unread ? '○ Mark read' : '● Mark unread');
      t.row.style.transform = `translateX(${Math.max(-160, Math.min(160, t.dx))}px)`;
    }
    if (t.mode === 'pull') {
      const h = Math.min(70, t.dy / 2);
      $('#ptr').style.height = h + 'px';
      $('#ptr').classList.toggle('on', h > 0);
      $('#ptrText').textContent = h >= 55 ? '↻ Release to refresh' : '↓ Pull to refresh';
    }
  }, { passive: true });

  const finish = () => {
    if (!t) return;
    clearTimeout(t.timer);
    if (t.mode === 'swipe') {
      const r = rowOf(t.row);
      const go = Math.abs(t.dx) > SWIPE_AT;
      if (go && r) {
        const keys = keysOfRow(r);
        if (t.dx < 0) { t.row.style.transform = 'translateX(-110%)'; t.row.classList.add('settle'); const u = t.under; setTimeout(() => { if (u) u.remove(); }, 400); deleteKeys(keys); }
        else { const unread = r.kind === 'thread' ? r.msgs.some(x => !x.seen) : !r.m.seen; endSwipe(); setSeen(keys, unread); }
      } else endSwipe();
      suppressClick = true;
    }
    if (t.mode === 'pull') {
      const pulled = parseFloat($('#ptr').style.height) >= 55;
      $('#ptr').style.height = '0px'; $('#ptr').classList.remove('on');
      if (pulled) { state.cur.page = 0; loadMessages({ quiet: true }); loadFolders(state.cur.accId); toast('Refreshed'); }
    }
    t = null;
  };
  list.addEventListener('touchend', finish);
  list.addEventListener('touchcancel', () => { if (t && t.mode === 'swipe') endSwipe(); if (t) clearTimeout(t.timer); t = null; $('#ptr').style.height = '0px'; });
  // a press-and-hold or a swipe is not also a tap
  list.addEventListener('click', e => { if (suppressClick) { suppressClick = false; e.stopPropagation(); e.preventDefault(); } }, true);
})();
