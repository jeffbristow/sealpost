/* =====================================================================
 * Sealpost — main.js  (Electron main process)
 * ---------------------------------------------------------------------
 * Starts the app window and connects the UI to the mail + PGP engines.
 * The UI (renderer) has NO direct Node/file access; everything goes
 * through the IPC handlers below (see preload.js for the bridge).
 *
 * Sections:
 *   1. Startup, window, security hardening
 *   2. IPC helper (uniform {ok,data}/{ok:false,error} replies)
 *   3. Settings + accounts
 *   4. Mailbox (folders, lists, reading, actions, sending)
 *   5. Attachments (save, decrypt, import keys)
 *   6. PGP key management
 *   7. PGP tools (encrypt/decrypt/sign/verify pasted text)
 *   8. Sync with my web server (1.4.0)
 * ===================================================================== */

const { app, BrowserWindow, ipcMain, dialog, shell, safeStorage, clipboard, Menu, powerMonitor, Notification } = require('electron');
const path = require('path');
const fs = require('fs');

const { Store } = require('./store');
const { PgpEngine } = require('./pgp');
const { MailService, isNetworkError } = require('./mail');
const { composeMessage, buildDraft } = require('./compose');
const { readMessage, readDraft } = require('./reader');
const { ContactStore } = require('./contacts');   // 1.1.0
const lockLib = require('./applock');               // 1.1.0
const backupLib = require('./backup');             // 1.2.0
const { CacheStore } = require('./cache');          // 1.3.0
const { SyncService } = require('./sync');          // 1.4.0
const presets = require('./presets');
const updateCheck = require('./updatecheck');      // 1.12.0
const { readPackageJson, fs: ofs } = require('./asarinfo'); // lock-free update reading (1.0.3)

let win, store, pgp, mail, contacts, cache, cloud;
let weakSecureStorage = false;   // 1.8.0: Linux without a login keyring
let appLocked = false;      // 1.1.0 app lock state
let lastActivity = Date.now();
const openMessages = new Map(); // "acc|folder|uid" -> view incl. attachment bytes (small LRU)

/* =================================================================
 * 1. STARTUP, WINDOW, SECURITY
 * ================================================================= */
const IS_MAC = process.platform === 'darwin';   // 1.11.0
if (!app.requestSingleInstanceLock()) app.quit();
app.on('second-instance', () => { if (win) { if (win.isMinimized()) win.restore(); win.focus(); } });
app.setAppUserModelId('com.sealpost.mail');

async function init() {
  const dataDir = app.getPath('userData');
  // Passwords encrypted with safeStorage:
  //   Windows -> DPAPI (your Windows login)
  //   Linux   -> GNOME Keyring / KDE Wallet (your login keyring)   (1.8.0)
  //   Mac     -> Keychain
  const secure = safeStorage.isEncryptionAvailable() ? {
    encrypt: s => safeStorage.encryptString(s).toString('base64'),
    decrypt: b => safeStorage.decryptString(Buffer.from(b, 'base64'))
  } : null;
  // 1.8.0: on Linux without a login keyring Electron falls back to a fixed
  // built-in key ("basic_text") — fine for keeping mail passwords out of
  // plain sight, NOT strong enough to remember PGP key passphrases.
  weakSecureStorage = process.platform === 'linux' && (() => {
    try { return /basic_text|unknown/.test(safeStorage.getSelectedStorageBackend()); } catch { return false; }
  })();
  // 1.8.0: keep the data folder private on Linux / Mac (only you can open it)
  if (process.platform !== 'win32') { try { fs.chmodSync(dataDir, 0o700); } catch { /* ignore */ } }
  store = new Store(dataDir, secure);
  pgp = new PgpEngine(dataDir, () => store.getSettings(), weakSecureStorage ? null : secure); // for remembered passphrases
  await pgp.load();
  mail = new MailService(store);
  // 1.1.0: contacts — a contact's assigned key is always used for that address
  contacts = new ContactStore(dataDir);
  pgp.setPinnedLookup(email => contacts.pinnedFor(email));
  cache = new CacheStore(dataDir); // 1.3.0: opens only when you unlock with your PIN
  // 1.4.0: sync with your own web server (accounts, contacts, keys, settings — end-to-end encrypted)
  cloud = new SyncService({
    dataDir, store, pgp, contacts, secure,
    appVersion: process.env.SEALPOST_RUNNING_VERSION || app.getVersion(),
    onEvent: (type, data) => sendEvent(type, data),
    onApplied: afterCloudApplied
  });
  // 1.1.0: start locked when the app lock is on
  appLocked = lockEnabled();
  const attemptsFile = path.join(dataDir, 'lock-attempts.json');
  lockLib.setAttemptStore({
    load: () => JSON.parse(fs.readFileSync(attemptsFile, 'utf8')),
    save: a => fs.writeFileSync(attemptsFile, JSON.stringify(a))
  });
}

/* ---------- App lock helpers (1.1.0) ---------- */
function lockCfg() { return store.getSettings().appLock || null; }
function lockEnabled() { const c = lockCfg(); return !!(c && c.enabled && c.hash); }

/* ---------- New app icon on existing shortcuts (1.3.1) ----------
 * An update file replaces Sealpost's code, not Sealpost.exe, and Windows
 * shortcuts show the .exe's icon. So we copy the new icon next to your
 * data and point Sealpost's own shortcuts (desktop, Start menu, pinned
 * taskbar) at it. Only shortcuts that open Sealpost.exe are touched.
 * The next full install puts the icon into Sealpost.exe itself. */
const ICON_VERSION = 'seal-1';
function refreshShortcutIcons() {
  if (process.platform !== 'win32') return;
  if (store.getSettings().shortcutIcon === ICON_VERSION) return;
  try {
    const iconDir = path.join(app.getPath('userData'), 'icons');
    fs.mkdirSync(iconDir, { recursive: true });
    const iconFile = path.join(iconDir, 'sealpost-' + ICON_VERSION + '.ico');
    fs.writeFileSync(iconFile, fs.readFileSync(path.join(__dirname, '..', 'renderer', 'app-icon.ico')));
    const appData = app.getPath('appData');
    const candidates = [
      path.join(app.getPath('desktop'), 'Sealpost.lnk'),
      path.join(appData, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Sealpost.lnk'),
      path.join(appData, 'Microsoft', 'Internet Explorer', 'Quick Launch', 'User Pinned', 'TaskBar', 'Sealpost.lnk')
    ];
    let updated = 0;
    for (const lnk of candidates) {
      if (!fs.existsSync(lnk)) continue;
      try {
        const info = shell.readShortcutLink(lnk);
        if (!/sealpost\.exe$/i.test(info.target || '')) continue; // not ours — leave it alone
        if (shell.writeShortcutLink(lnk, 'update', { icon: iconFile, iconIndex: 0 })) updated++;
      } catch (e) { console.warn('Shortcut icon not updated:', lnk, e.message); }
    }
    store.setSettings({ shortcutIcon: ICON_VERSION });
    console.log('Shortcut icons updated:', updated);
  } catch (e) { console.warn('Shortcut icon refresh failed', e.message); }
}

/* ---------- Instant new mail: push events -> window (1.2.0) ---------- */
function sendEvent(type, data) {
  if (win && !win.isDestroyed() && !appLocked) win.webContents.send('sealpost:event', { type, data });
}

function onPush(type, data) {
  // 1.3.0: push connection state tells us whether an account is reachable
  if (type === 'status') {
    if (data.state === 'offline') markOffline(data.accId);
    else if (data.state === 'live' || data.state === 'polling') markOnline(data.accId);
  }
  if (type === 'new' && cacheOn()) {
    try { cache.upsertSummaries(data.accId, 'INBOX', data.messages); } catch { /* ignore */ }
    scheduleSync(8000); // fetch the new messages' content for offline use
  }
  if (type === 'new' && data.messages.length) {
    if (win && !win.isDestroyed() && !win.isFocused()) win.flashFrame(true); // taskbar button flashes
    // while locked the window can't show anything — give a notice without any details
    if (appLocked && store.getSettings().notifyNewMail !== false && Notification.isSupported()) {
      new Notification({ title: 'Sealpost', body: 'New mail arrived', silent: false }).show();
    }
  }
  sendEvent(type, data);
}

function applyPushSetting() {
  if (store.getSettings().pushMail === false) { mail.stopAllWatches(); return; }
  for (const a of store.listAccounts()) mail.startWatch(a.id);
}

/* =================================================================
 * SYNC WITH MY WEB SERVER (1.4.0) — scheduling + reacting to changes
 * ================================================================= */
let cloudTimer = null;
/** Sync a few seconds after something changed (changes close together are sent together). */
function cloudSyncSoon(ms = 4000) {
  if (!cloud || !cloud.connected()) return;
  clearTimeout(cloudTimer);
  cloudTimer = setTimeout(() => { if (!appLocked) cloud.sync('change'); }, ms);
}

/** Requests that change accounts, contacts, keys or settings -> upload soon. */
const CLOUD_MUTATING = /^(accounts:(save|delete|setPrefs)|mail:(renameFolder|deleteFolder)|contacts:(save|delete|pinKey|importKeyFor|fromMessage)|pgp:(generate|importText|importFile|delete|setTrust|revoke|changePassphrase|extendExpiry|syncPassphrase|unsyncPassphrase)|att:importKey|mail:importAutocrypt|settings:set|backup:restore)$/;

/** Things arrived from another device: reconnect changed accounts, refresh key slots. */
async function afterCloudApplied(changes) {
  for (const id of changes.accounts || []) {
    try { await mail.stopWatch(id); await mail.disconnect(id); } catch { /* not connected */ }
  }
  if ((changes.accounts && changes.accounts.length) || changes.settings) applyPushSetting();
  if (changes.secretKeys && cache && cache.isOpen()) { try { await cache.rewrapPgp(pgp); } catch { /* ignore */ } }
}

/* =================================================================
 * OFFLINE CACHE + OUTBOX (1.3.0)
 * ================================================================= */
const offlineDefaults = { enabled: false, days: 30, maxMsgMB: 10, capMB: 500 };
const offlineCfg = () => ({ ...offlineDefaults, ...(store.getSettings().offline || {}) });
const cacheOn = () => offlineCfg().enabled && cache.exists() && cache.isOpen();
const offlineAccounts = new Set();
let syncing = false, flushing = false, lastSync = null;

function markOffline(accId) {
  if (offlineAccounts.has(accId)) return;
  offlineAccounts.add(accId);
  sendEvent('net', { accId, offline: true });
}
function markOnline(accId) {
  if (!offlineAccounts.has(accId)) return;
  offlineAccounts.delete(accId);
  sendEvent('net', { accId, offline: false });
  setTimeout(() => flushQueues(), 500); // send what waited in the Outbox
}
// known-offline account (push connection is down): go straight to saved mail instead of waiting for timeouts
const fastOffline = accId => cacheOn() && (offlineAccounts.has(accId) || mail.watchStatus()[accId] === 'offline');

function offlineError(msg) { const e = new Error(msg); e.code = 'OFFLINE'; return e; }

/** Try the server; if the network is down and the cache is on, use the fallback. */
async function netOr(accId, online, fallback) {
  if (fastOffline(accId) && fallback) {
    const r = await fallback();
    if (r !== undefined) return r;
  }
  try {
    const r = await online();
    markOnline(accId);
    return r;
  } catch (e) {
    if (!isNetworkError(e)) throw e;
    markOffline(accId);
    if (cacheOn() && fallback) {
      const r = await fallback();
      if (r !== undefined) return r;
    }
    throw offlineError(cacheOn() ? 'You\'re offline and this isn\'t saved on this PC.' : 'You\'re offline. Turn on "Offline mail" in Settings to keep mail available without a connection.');
  }
}

/** Background sync of all accounts into the cache. */
async function runSync() {
  if (!cacheOn() || syncing || appLocked) return;
  syncing = true;
  sendEvent('sync', { running: true });
  const cfg = offlineCfg();
  try {
    for (const a of store.listAccounts()) {
      if (offlineAccounts.has(a.id)) continue;
      try {
        await mail.syncAccount(a.id, cache, { days: cfg.days, maxSize: cfg.maxMsgMB * 1048576, shouldStop: () => appLocked || !cacheOn() });
        markOnline(a.id);
      } catch (e) {
        if (isNetworkError(e)) markOffline(a.id);
        else console.warn('Sync failed', a.email, e.message);
      }
    }
    if (cacheOn()) cache.enforceCap(cfg.capMB * 1048576, store.listAccounts().map(a => a.id));
    lastSync = new Date().toISOString();
  } finally {
    syncing = false;
    sendEvent('sync', { running: false, lastSync });
  }
}
let syncTimer = null;
function scheduleSync(ms = 10000) { clearTimeout(syncTimer); syncTimer = setTimeout(runSync, ms); }

/** Replay what was queued while offline: flag changes, drafts, then the Outbox. */
async function flushQueues() {
  if (!cacheOn() || flushing || appLocked) return;
  flushing = true;
  try {
    // 1. read / flagged changes
    const pending = cache.getQueue('pending');
    const keep = [];
    for (const op of pending) {
      try { await mail.setFlag(op.accId, op.folder, op.uid, op.flag, op.on, op.uidValidity); markOnline(op.accId); }
      catch (e) { if (isNetworkError(e)) { markOffline(op.accId); keep.push(op); } /* else: message gone — drop */ }
    }
    cache.saveQueue('pending', keep);

    // 2. drafts saved on this PC -> server Drafts folder
    const drafts = cache.getQueue('drafts');
    const keepD = [];
    for (const d of drafts) {
      try {
        const built = await buildDraft(pgp, store.getAccount(d.accId), d.draft);
        const r = await mail.saveDraft(d.accId, built.raw, { messageId: built.messageId });
        uploadedLocalDrafts.set(d.id, { accId: d.accId, folder: r.folder, uid: r.uid });
        markOnline(d.accId);
      } catch (e) { if (isNetworkError(e)) { markOffline(d.accId); keepD.push(d); } else { d.error = e.message; keepD.push(d); } }
    }
    cache.saveQueue('drafts', keepD);

    // 3. Outbox
    const out = cache.outbox();
    const keepO = [];
    let sent = 0;
    for (const item of out) {
      if (offlineAccounts.has(item.accId) && item.tried) { keepO.push(item); continue; }
      try {
        await mail.send(item.accId, { raw: Buffer.from(item.raw, 'base64'), envelope: item.envelope, messageId: item.messageId });
        sent++;
        markOnline(item.accId);
        await afterSent(item.accId, item.meta || {});
      } catch (e) {
        item.tried = true;
        if (isNetworkError(e)) { markOffline(item.accId); keepO.push(item); }
        else { item.error = e.message; keepO.push(item); } // e.g. recipient rejected — you decide
      }
    }
    cache.saveQueue('outbox', keepO);
    if (sent || pending.length !== keep.length || drafts.length !== keepD.length) sendEvent('outbox', { sent, waiting: keepO.length });
  } finally { flushing = false; }
}
const uploadedLocalDrafts = new Map(); // local draft id -> server draft (uploaded while the composer was open)

/** Bookkeeping after a message really went out (now or from the Outbox). */
async function afterSent(accId, meta) {
  if (meta.replyToUid && meta.replyFolder) await mail.markAnswered(accId, meta.replyFolder, meta.replyToUid);
  if (meta.draftFolder === '__local__') {
    if (cacheOn()) cache.saveQueue('drafts', cache.getQueue('drafts').filter(d => d.id !== meta.draftUid));
    const up = uploadedLocalDrafts.get(meta.draftUid);
    if (up) { try { await mail.deleteDraft(up.accId, up.folder, up.uid); } catch { /* ignore */ } uploadedLocalDrafts.delete(meta.draftUid); }
  } else if (meta.draftUid && meta.draftFolder) {
    try { await mail.deleteDraft(accId, meta.draftFolder, meta.draftUid); } catch { /* ignore */ }
  }
}

/** Open the cache with the PIN / key passphrase used to unlock Sealpost. */
async function openCacheAfterUnlock({ pin, passphrase }) {
  if (!offlineCfg().enabled || !cache.exists()) return;
  let ok = false;
  if (pin) ok = cache.unlockWithPin(pin);
  else if (passphrase) ok = await cache.unlockWithPgp(await pgp.decryptedKeysFor(passphrase));
  if (ok) { setTimeout(() => flushQueues(), 2000); scheduleSync(5000); }
}

function lockApp(reason) {
  if (!lockEnabled() || appLocked) return;
  appLocked = true;
  pgp.lockAll();                 // forget unlocked keys too
  cache.lock();                  // 1.3.0: offline cache key leaves memory
  openMessages.clear();          // and any opened message content
  if (win && !win.isDestroyed()) win.webContents.reload(); // UI restarts behind the lock screen
  console.log('Sealpost locked:', reason);
}

function createWindow() {
  win = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 980,
    minHeight: 600,
    backgroundColor: '#14161a',
    title: 'Sealpost',
    // 1.3.1: seal icon (.ico on Windows for crisp taskbar/title-bar sizes)
    icon: path.join(__dirname, '..', 'renderer', process.platform === 'win32' ? 'app-icon.ico' : 'icon.png'),
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: true
    }
  });
  Menu.setApplicationMenu(IS_MAC ? macMenu() : null);   // 1.11.0: a Mac needs its menu bar (⌘C / ⌘V / ⌘Q …)
  win.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));

  // Links (including those inside emails) open in the real browser, never in-app
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^(https?|mailto):/i.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
  win.webContents.on('will-navigate', e => e.preventDefault());

  // Developer tools: Ctrl+Shift+I   Reload UI: Ctrl+R
  win.webContents.on('before-input-event', (e, input) => {
    if (input.control && input.shift && input.key.toLowerCase() === 'i' && !appLocked) win.webContents.toggleDevTools();
  });
}

/* ---------- 1.11.0: the Mac menu bar ----------
 * Without one, macOS has no ⌘C / ⌘V / ⌘A / ⌘Z / ⌘Q. Select All asks the
 * window first, so ⌘A in the message list selects messages (as Ctrl+A does). */
function macMenu() {
  const toWindow = type => () => sendEvent('menu', type);
  return Menu.buildFromTemplate([
    { label: 'Sealpost', submenu: [
      { role: 'about', label: 'About Sealpost' },
      { type: 'separator' },
      { label: 'Settings…', accelerator: 'Cmd+,', click: toWindow('settings') },
      { type: 'separator' },
      { role: 'hide', label: 'Hide Sealpost' }, { role: 'hideOthers' }, { role: 'unhide' },
      { type: 'separator' },
      { role: 'quit', label: 'Quit Sealpost' }
    ] },
    { label: 'Edit', submenu: [
      { role: 'undo' }, { role: 'redo' }, { type: 'separator' },
      { role: 'cut' }, { role: 'copy' }, { role: 'paste' }, { role: 'pasteAndMatchStyle' }, { role: 'delete' },
      { label: 'Select All', accelerator: 'Cmd+A', click: () => (appLocked ? win && win.webContents.selectAll() : sendEvent('menu', 'selectAll')) }
    ] },
    { label: 'View', submenu: [{ role: 'resetZoom' }, { role: 'zoomIn' }, { role: 'zoomOut' }, { type: 'separator' }, { role: 'togglefullscreen' }] },
    { role: 'windowMenu' }
  ]);
}

app.whenReady().then(async () => {
  await init();
  registerIpc();
  createWindow();
  refreshShortcutIcons(); // 1.3.1
  // 1.2.0: instant new mail — one IDLE connection per account
  mail.onPush = onPush;
  applyPushSetting();
  powerMonitor.on('resume', () => { mail.restartWatches(); cloudSyncSoon(15000); }); // reconnect after sleep
  // 1.4.0: sync with the web server shortly after start, then every 5 minutes
  cloudSyncSoon(8000);
  setInterval(() => { if (!appLocked && cloud.connected()) cloud.sync('timer'); }, 5 * 60 * 1000);
  // 1.3.0: keep the offline cache fresh + retry the Outbox
  setInterval(() => runSync(), 15 * 60 * 1000);
  setInterval(() => { if (cacheOn() && (cache.outbox().length || cache.getQueue('pending').length || cache.getQueue('drafts').length)) flushQueues(); }, 60 * 1000);
  // app lock off -> there's no PIN, so no cache (cache needs the PIN)
  if (!lockEnabled() && cache.exists()) { cache.destroy(); store.setSettings({ offline: { ...offlineCfg(), enabled: false } }); }
  win.on('focus', () => win.flashFrame(false));
  // 1.1.0: lock when Windows locks / sleeps, and after inactivity
  powerMonitor.on('lock-screen', () => lockApp('Windows locked'));
  powerMonitor.on('suspend', () => lockApp('computer sleeping'));
  setInterval(() => {
    const c = lockCfg();
    const mins = c && Number(c.idleMinutes);
    if (lockEnabled() && !appLocked && mins > 0 && Date.now() - lastActivity > mins * 60000) lockApp('inactive');
  }, 20000);
});

app.on('window-all-closed', async () => {
  pgp && pgp.lockAll();
  if (mail) { await mail.stopAllWatches(); await mail.disconnectAll(); }
  app.quit();
});

/* =================================================================
 * 2. IPC HELPER
 * ================================================================= */
// While the app is locked only these requests are answered (1.1.0)
const ALLOWED_WHILE_LOCKED = new Set(['lock:status', 'lock:unlockPin', 'lock:unlockHello', 'lock:unlockPassphrase', 'app:info']);

function handle(channel, fn) {
  ipcMain.handle(channel, async (_e, ...args) => {
    if (appLocked && !ALLOWED_WHILE_LOCKED.has(channel)) {
      return { ok: false, error: 'Sealpost is locked', code: 'LOCKED' };
    }
    try {
      const data = await fn(...args);
      if (CLOUD_MUTATING.test(channel)) { cloud.noteLocalChange(); cloudSyncSoon(); } // 1.4.0
      return { ok: true, data };
    } catch (err) {
      return {
        ok: false,
        error: err.message || String(err),
        code: err.code || null,
        fingerprint: err.fingerprint || null,
        userId: err.userId || null,
        missing: err.missing || null,
        canRemember: !!err.canRemember
      };
    }
  });
}

// compare version strings: 1 if a>b, -1 if a<b, 0 if equal
function cmpVersion(a, b) {
  const pa = String(a).split('.').map(n => parseInt(n, 10) || 0);
  const pb = String(b).split('.').map(n => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d > 0 ? 1 : -1;
  }
  return 0;
}

async function saveDialog(defaultPath, content, filters) {
  const r = await dialog.showSaveDialog(win, { defaultPath, filters });
  if (r.canceled || !r.filePath) return null;
  fs.writeFileSync(r.filePath, content);
  return r.filePath;
}

/* =================================================================
 * Contacts <-> keys helpers (1.1.0)
 * ================================================================= */

// Import keys, then give each new key to a contact with that address who has no key yet
async function importKeys(data) {
  const result = await pgp.importKeys(data);
  if (result.secret.length && cache && cache.isOpen()) await cache.rewrapPgp(pgp); // 1.3.0
  for (const fp of [...result.imported, ...result.updated]) {
    const key = pgp.publicKeys.get(fp);
    if (!key) continue;
    for (const e of pgp._emailsOf(key)) {
      const c = contacts.byEmail(e);
      if (c && !c.keyFp) contacts.pinKey(c.id, fp);
    }
  }
  return result;
}

/**
 * Who sent this message, is the sender a contact, and does the key they
 * signed with (or offered) match the key assigned to them?
 * status:
 *   ok                 signer/offered key matches the contact's key
 *   key-changed        signed with / offering a DIFFERENT key than assigned  -> warning
 *   offer-assign       contact has no key; message offers or was signed by one
 *   offer-add          not a contact; message offers or was signed by a key
 *   contact            contact, nothing to compare
 *   none               not a contact, no key involved
 */
async function senderKeyInfo(view) {
  const from = view.from && view.from[0] && (view.from[0].address || '').toLowerCase();
  if (!from) return null;
  const contact = contacts.byEmail(from);

  // a key the sender sent along (Autocrypt header or attached .asc)
  let offered = null;
  try {
    if (view.autocryptKey) offered = await pgp.peekKey(Buffer.from(view.autocryptKey, 'base64'));
    else {
      const a = view.attachments.find(x => x.isKey);
      if (a) offered = await pgp.peekKey(a.content);
    }
  } catch { offered = null; }
  if (offered && !offered.emails.includes(from)) offered = null; // not the sender's own key

  const sig = view.pgp.signatures[0] || null;
  const signerFp = sig && sig.valid && sig.fingerprint ? sig.fingerprint : null;
  const signerKeyId = sig ? sig.keyId : null;

  let status = 'none', changedTo = null;
  if (contact && contact.keyFp) {
    const pinnedKey = pgp.publicKeys.get(contact.keyFp);
    const pinnedIds = pinnedKey ? pinnedKey.getKeys().map(k => k.getKeyID().toHex().toUpperCase()) : [];
    if (signerKeyId && !pinnedIds.includes(signerKeyId) && !(signerFp && signerFp === contact.keyFp)) {
      status = 'key-changed'; changedTo = signerFp || signerKeyId;
    } else if (offered && offered.fingerprint !== contact.keyFp) {
      status = 'key-changed'; changedTo = offered.fingerprint;
    } else status = 'ok';
  } else if (offered || signerFp) {
    status = contact ? 'offer-assign' : 'offer-add';
  } else status = contact ? 'contact' : 'none';

  const candidateFp = offered ? offered.fingerprint : signerFp;
  return {
    email: from,
    name: (view.from[0].name || '').trim(),
    contact: contact ? { id: contact.id, name: contact.name, keyFp: contact.keyFp } : null,
    status, changedTo, candidateFp,
    candidateInKeyring: candidateFp ? pgp.publicKeys.has(candidateFp) : false,
    offeredArmored: offered ? offered.armored : null
  };
}

function registerIpc() {
  /* =================================================================
   * 3. SETTINGS + ACCOUNTS
   * ================================================================= */
  // appLock holds the PIN hash: never send it to the window, never let the window overwrite it
  const publicSettings = () => { const { appLock, ...s } = store.getSettings(); return s; };
  handle('settings:get', () => publicSettings());
  handle('settings:set', patch => {
    const { appLock, ...rest } = patch || {};
    const pushBefore = store.getSettings().pushMail !== false;
    store.setSettings(rest);
    if ((store.getSettings().pushMail !== false) !== pushBefore) applyPushSetting(); // 1.2.0
    return publicSettings();
  });

  handle('accounts:list', () => store.listAccounts());
  handle('accounts:presets', () => presets);
  handle('accounts:save', async acc => {
    const saved = store.saveAccount(acc);
    await mail.disconnect(saved.id); // reconnect with new settings
    await mail.stopWatch(saved.id);  // 1.2.0: push connection too
    if (store.getSettings().pushMail !== false) mail.startWatch(saved.id);
    return saved;
  });
  handle('accounts:delete', async id => { await mail.stopWatch(id); await mail.disconnect(id); store.deleteAccount(id); return true; });
  handle('accounts:test', async acc => {
    // use stored password if the form left it blank (editing existing account)
    let full = { ...acc };
    if (acc.id && !acc.password) {
      const stored = store.getAccount(acc.id);
      full.password = stored.password;
      full.smtpPassword = acc.smtpPassword || stored.smtpPassword;
    } else full.smtpPassword = acc.smtpPassword || acc.password;
    full.imapPort = Number(full.imapPort); full.smtpPort = Number(full.smtpPort);
    return mail.test(full);
  });

  /* =================================================================
   * 4. MAILBOX
   * ================================================================= */
  // 1.3.0: every mail action falls back to the offline cache when the network is down
  handle('mail:folders', accId => netOr(accId,
    async () => { const f = await mail.listFolders(accId); if (cacheOn()) cache.saveFolders(accId, f); return f; },
    () => { const f = cache.getFolders(accId); return f ? f.map(x => ({ ...x, offline: true })) : undefined; }));

  // 1.9.2: what's saved on this PC, straight away (no network). The screen
  // shows this at once and then swaps in the server's answer. null = nothing saved.
  handle('mail:foldersCached', accId => {
    if (!cacheOn()) return null;
    const f = cache.getFolders(accId);
    return f && f.length ? MailService.folderTree(f.map(x => ({ ...x }))) : null;
  });
  handle('mail:listCached', (accId, folder, opts) => {
    if (!cacheOn()) return null;
    const idx = cache.getIndex(accId, folder);
    if (!idx || !Object.keys(idx.messages || {}).length) return null;
    return cache.listMessages(accId, folder, { pageSize: store.getSettings().pageSize, ...opts });
  });

  handle('mail:list', (accId, folder, opts) => {
    const o = { pageSize: store.getSettings().pageSize, ...opts };
    return netOr(accId,
      async () => {
        const res = await mail.listMessages(accId, folder, o);
        if (cacheOn()) {
          const idx = cache.upsertSummaries(accId, folder, res.messages, res.uidValidity);
          for (const m of res.messages) m.cached = !!idx.bodies[m.uid];
        }
        return res;
      },
      () => cache.listMessages(accId, folder, o));
  });

  handle('mail:open', async (accId, folder, uid) => {
    // 1.3.0: a saved copy opens instantly (and works offline); the server is told it was read
    let raw = null, fromCache = false;
    if (cacheOn() && cache.hasBody(accId, folder, uid)) {
      raw = cache.getBody(accId, folder, uid);
      fromCache = !!raw;
    }
    if (raw) {
      const m = cache.getIndex(accId, folder).messages[uid];
      if (m && !m.seen) {
        cache.setFlag(accId, folder, uid, '\\Seen', true);
        mail.setFlag(accId, folder, uid, '\\Seen', true).catch(e => {
          if (isNetworkError(e)) { markOffline(accId); cache.pushQueue('pending', { accId, folder, uid, flag: '\\Seen', on: true, uidValidity: cache.getIndex(accId, folder).uidValidity }); }
        });
      }
    } else {
      raw = await netOr(accId, () => mail.getRaw(accId, folder, uid), () => undefined);
      if (cacheOn()) { try { cache.putBody(accId, folder, uid, raw); cache.setFlag(accId, folder, uid, '\\Seen', true); } catch { /* ignore */ } }
    }
    const view = await readMessage(raw, pgp);
    const key = accId + '|' + folder + '|' + uid;
    const sender = await senderKeyInfo(view);           // 1.1.0 contacts + key-change check
    openMessages.set(key, { view, raw, sender });
    if (openMessages.size > 25) openMessages.delete(openMessages.keys().next().value);
    const { offeredArmored, ...senderPublic } = sender || {};
    return { ...view, key, sender: sender ? senderPublic : null, attachments: view.attachments.map(({ content, ...a }) => a) };
  });

  handle('mail:source', key => {
    const m = openMessages.get(key);
    if (!m) throw new Error('Open the message first');
    return m.raw.toString('utf8');
  });

  handle('mail:flag', (accId, folder, uids, flag, on) => netOr(accId,
    async () => { const r = await mail.setFlag(accId, folder, uids, flag, on); if (cacheOn()) cache.setFlag(accId, folder, uids, flag, on); return r; },
    () => { // offline: change it here now, tell the server later
      cache.setFlag(accId, folder, uids, flag, on);
      const uv = cache.getIndex(accId, folder).uidValidity;
      for (const uid of [].concat(uids)) cache.pushQueue('pending', { accId, folder, uid, flag, on, uidValidity: uv });
      return { queued: true };
    }));
  // 1.6.0: mark a whole folder as read (offline: in the saved copy now, on the server later)
  handle('mail:markFolderRead', (accId, folder) => netOr(accId,
    async () => {
      const uids = await mail.markFolderRead(accId, folder);
      if (cacheOn() && uids.length) cache.setFlag(accId, folder, uids, '\\Seen', true);
      return { count: uids.length };
    },
    () => {
      const idx = cache.getIndex(accId, folder);
      const uids = Object.values(idx.messages).filter(m => !m.seen).map(m => m.uid);
      cache.setFlag(accId, folder, uids, '\\Seen', true);
      for (const uid of uids) cache.pushQueue('pending', { accId, folder, uid, flag: '\\Seen', on: true, uidValidity: idx.uidValidity });
      return { count: uids.length, queued: true };
    }));
  // move/delete wait for a connection: doing them offline could clash with changes made on your phone
  const notOffline = () => { throw offlineError('Moving and deleting need a connection. Try again when you\'re back online.'); };
  handle('mail:move', (accId, folder, uids, target) => netOr(accId,
    async () => { const r = await mail.move(accId, folder, uids, target); if (cacheOn()) cache.removeUids(accId, folder, [].concat(uids)); return r; }, notOffline));
  handle('mail:delete', (accId, folder, uids) => netOr(accId,
    async () => { const r = await mail.remove(accId, folder, uids); if (cacheOn()) cache.removeUids(accId, folder, [].concat(uids)); return r; }, notOffline));
  handle('mail:createFolder', (accId, name) => mail.createFolder(accId, name));

  /* ---------- 1.10.0: folder management ----------
   * Rename (also used to move a folder under another one) and delete.
   * Folders are server changes, so they need a connection. Pins follow a
   * renamed folder and disappear with a deleted one. */
  const folderPaths = async (accId, root) => {
    const f = await mail.listFolders(accId);
    const d = (f.find(x => x.path === root) || f[0] || {}).delimiter || '/';
    return { delim: d, under: f.map(x => x.path).filter(p => p === root || p.startsWith(root + d)) };
  };
  handle('mail:renameFolder', (accId, from, to) => netOr(accId, async () => {
    const { delim, under } = await folderPaths(accId, from);
    await mail.renameFolder(accId, from, to);
    if (cacheOn()) for (const p of under) cache.dropFolder(accId, p);
    const acc = store.listAccounts().find(a => a.id === accId);
    const moved = p => (p === from ? to : p.startsWith(from + delim) ? to + p.slice(from.length) : p);
    if (acc && (acc.pinnedFolders || []).some(p => moved(p) !== p)) store.setAccountPrefs(accId, { pinnedFolders: acc.pinnedFolders.map(moved) });
    return true;
  }, () => { throw offlineError('Renaming folders needs a connection.'); }));
  handle('mail:deleteFolder', (accId, folderPath) => netOr(accId, async () => {
    const { delim, under } = await folderPaths(accId, folderPath);
    await mail.deleteFolder(accId, folderPath);
    if (cacheOn()) for (const p of under) cache.dropFolder(accId, p);
    const acc = store.listAccounts().find(a => a.id === accId);
    const gone = p => p === folderPath || p.startsWith(folderPath + delim);
    if (acc && (acc.pinnedFolders || []).some(gone)) store.setAccountPrefs(accId, { pinnedFolders: acc.pinnedFolders.filter(p => !gone(p)) });
    return true;
  }, () => { throw offlineError('Deleting folders needs a connection.'); }));
  // pins + conversation view switch (synced to your other devices)
  handle('accounts:setPrefs', (accId, prefs) => store.setAccountPrefs(accId, prefs || {}));

  /* ---------- 1.10.0: All Inboxes ----------
   * The Inbox of every account in one list, newest first. Each message
   * says which account it belongs to. Accounts that can't be reached
   * (and have nothing saved) are skipped and reported. */
  const allInboxes = async (opts, cachedOnly) => {
    const pageSize = Number(store.getSettings().pageSize) || 50;
    const page = Math.max(0, Number(opts.page) || 0);
    const want = { page: 0, pageSize: (page + 1) * pageSize, search: opts.search || '' };
    const accounts = store.listAccounts();
    const errors = [];
    let total = 0, more = false, offline = false;
    const lists = await Promise.all(accounts.map(async a => {
      try {
        let r;
        if (cachedOnly) {
          if (!cacheOn()) return [];
          const idx = cache.getIndex(a.id, 'INBOX');
          if (!idx || !Object.keys(idx.messages || {}).length) return [];
          r = cache.listMessages(a.id, 'INBOX', want);
        } else {
          r = await netOr(a.id, async () => {
            const res = await mail.listMessages(a.id, 'INBOX', want);
            if (cacheOn()) {
              const idx = cache.upsertSummaries(a.id, 'INBOX', res.messages, res.uidValidity);
              for (const m of res.messages) m.cached = !!idx.bodies[m.uid];
            }
            return res;
          }, () => cache.listMessages(a.id, 'INBOX', want));
        }
        total += r.total || 0; more = more || !!r.hasMore; offline = offline || !!r.offline;
        return r.messages.map(m => ({ ...m, accId: a.id, folder: 'INBOX' }));
      } catch (e) { errors.push(a.email + ': ' + e.message); return []; }
    }));
    const all = lists.flat().sort((x, y) => new Date(y.date) - new Date(x.date));
    const messages = all.slice(page * pageSize, (page + 1) * pageSize);
    return { total, messages, hasMore: more || all.length > (page + 1) * pageSize, offline, errors };
  };
  handle('mail:listUnified', opts => allInboxes(opts || {}, false));
  handle('mail:listUnifiedCached', opts => allInboxes(opts || {}, true));

  handle('mail:send', async (accId, draft) => {
    const acc = store.getAccount(accId);
    const built = await composeMessage(pgp, acc, draft); // encrypted + signed right now, even if it has to wait
    const meta = { replyToUid: draft.replyToUid, replyFolder: draft.replyFolder, draftUid: draft.draftUid, draftFolder: draft.draftFolder };
    let res;
    try {
      if (fastOffline(accId)) throw Object.assign(new Error('offline'), { code: 'ECONNREFUSED' });
      res = await mail.send(accId, built);
      markOnline(accId);
    } catch (e) {
      if (!isNetworkError(e)) throw e;
      markOffline(accId);
      if (!cacheOn()) throw offlineError('You\'re offline. Turn on "Offline mail" in Settings to queue messages in the Outbox.');
      // 1.3.0: Outbox — sent automatically when the connection returns
      cache.addOutbox({ accId, raw: built.raw, envelope: built.envelope, messageId: built.messageId, meta,
        summary: { to: draft.to, subject: draft.hideSubject ? '(hidden subject)' : draft.subject, encrypted: !!draft.encrypt, signed: !!draft.sign } });
      sendEvent('outbox', { sent: 0, waiting: cache.outbox().length });
      return { queued: true };
    }
    // 1.1.0: the message is sent, so its saved draft is no longer needed
    await afterSent(accId, meta);
    // remember new correspondents as contacts (without a key) so autocomplete knows them
    if (store.getSettings().autoAddContacts !== false) {
      for (const a of require('./mime').parseAddressList([draft.to, draft.cc, draft.bcc].filter(Boolean).join(','))) {
        try { contacts.ensure(a.address, a.name); } catch { /* ignore */ }
      }
    }
    return res;
  });

  handle('dialog:pickFiles', async () => {
    const r = await dialog.showOpenDialog(win, { properties: ['openFile', 'multiSelections'] });
    if (r.canceled) return [];
    return r.filePaths.map(p => ({ path: p, name: path.basename(p), size: fs.statSync(p).size }));
  });

  handle('shell:openExternal', url => {
    if (/^(https?|mailto):/i.test(url)) shell.openExternal(url);
    return true;
  });

  /* ---------- App version + in-app updates (added 1.0.1) ----------
   * An update file (.sealpost) is the app's code package. It is checked,
   * copied to %APPDATA%\Sealpost\updates\, and loaded by bootstrap.js on
   * the next start. Your accounts, settings and keys are not touched.
   * 1.12.0: "Check for updates" finds and downloads it from GitHub. */
  handle('app:info', () => ({
    version: process.env.SEALPOST_RUNNING_VERSION || app.getVersion(),
    installedVersion: app.getVersion(),
    fromUpdate: !!process.env.SEALPOST_UPDATE_FILE
  }));

  // 1.12.0: the checks + install step, shared by "Install update file…" and
  // "Check for updates" (which downloads the file from GitHub first).
  // <incoming> is a temporary file in the updates folder; it is moved or deleted.
  function installUpdateFrom(incoming) {
    const dir = path.dirname(incoming);
    let pkg;
    try {
      pkg = readPackageJson(incoming);
      if (pkg.name !== 'sealpost') throw new Error('not a Sealpost package');
      if (!pkg.__hasMain) throw new Error('app code missing');
    } catch (e) {
      try { ofs.unlinkSync(incoming); } catch { /* ignore */ }
      throw new Error('That file is not a valid Sealpost update (' + e.message + ')');
    }
    const current = process.env.SEALPOST_RUNNING_VERSION || app.getVersion();
    if (cmpVersion(pkg.version, current) <= 0) {
      try { ofs.unlinkSync(incoming); } catch { /* ignore */ }
      throw new Error(`This update is version ${pkg.version}; you already have ${current}.`);
    }
    const finalPath = path.join(dir, 'sealpost-' + pkg.version + '.asar');
    try { ofs.unlinkSync(finalPath); } catch { /* not there */ }
    ofs.renameSync(incoming, finalPath);
    // a version previously marked bad gets a fresh chance when re-installed
    try {
      const badFile = path.join(dir, 'bad-versions.json');
      const bad = JSON.parse(ofs.readFileSync(badFile, 'utf8')).filter(v => v !== pkg.version);
      ofs.writeFileSync(badFile, JSON.stringify(bad));
    } catch { /* none */ }
    return { version: pkg.version, from: current };
  }

  const updatesDir = () => {
    const dir = path.join(app.getPath('userData'), 'updates');
    fs.mkdirSync(dir, { recursive: true });
    return dir;
  };

  handle('app:installUpdate', async () => {
    const r = await dialog.showOpenDialog(win, {
      title: 'Choose a Sealpost update file',
      properties: ['openFile'],
      filters: [{ name: 'Sealpost update', extensions: ['sealpost'] }]
    });
    if (r.canceled || !r.filePaths[0]) return null;
    // 1.0.3 FIX (EBUSY on Windows): copy to a temporary .tmp name and read it with
    // asarinfo.js, which closes the file right away. Electron's own asar reader kept
    // the file open, so Windows refused to rename it.
    const incoming = path.join(updatesDir(), 'incoming-' + Date.now() + '.tmp');
    ofs.copyFileSync(r.filePaths[0], incoming);
    return installUpdateFrom(incoming);
  });

  // 1.12.0: updates come from the GitHub releases (updatecheck.js)
  handle('app:checkUpdate', () => updateCheck.checkForUpdate({ current: process.env.SEALPOST_RUNNING_VERSION || app.getVersion() }));

  handle('app:downloadUpdate', async () => {
    const info = await updateCheck.checkForUpdate({ current: process.env.SEALPOST_RUNNING_VERSION || app.getVersion() });
    if (!info.newer) throw new Error(`You already have the newest version (${info.current}).`);
    if (!info.file) throw new Error(`Version ${info.latest} has no update file. Download the installer from the release page instead.`);
    const incoming = path.join(updatesDir(), 'incoming-' + Date.now() + '.tmp');
    try { await updateCheck.downloadUpdate(info.file.url, incoming); }
    catch (e) { try { ofs.unlinkSync(incoming); } catch { /* ignore */ } throw e; }
    return installUpdateFrom(incoming);
  });

  handle('app:releasesPage', () => { shell.openExternal(updateCheck.RELEASES_PAGE); return true; });

  handle('app:restart', () => { app.relaunch(); app.exit(0); return true; });

  handle('clipboard:write', text => { clipboard.writeText(text); return true; });
  handle('clipboard:read', () => clipboard.readText());

  /* =================================================================
   * 5. ATTACHMENTS
   * ================================================================= */
  function attachmentOf(key, index) {
    const m = openMessages.get(key);
    if (!m) throw new Error('Message is no longer open');
    const a = m.view.attachments[index];
    if (!a) throw new Error('Attachment not found');
    return { m, a };
  }

  handle('att:save', async (key, index) => {
    const { a } = attachmentOf(key, index);
    return saveDialog(a.filename, a.content);
  });

  handle('att:open', async (key, index) => {
    // write to a temp folder then open with the Windows default app
    const { a } = attachmentOf(key, index);
    const dir = path.join(app.getPath('temp'), 'sealpost-attachments');
    fs.mkdirSync(dir, { recursive: true });
    const p = path.join(dir, a.filename.replace(/[\\/:*?"<>|]/g, '_'));
    fs.writeFileSync(p, a.content);
    const err = await shell.openPath(p);
    if (err) throw new Error(err);
    return p;
  });

  handle('att:decrypt', async (key, index) => {
    const { a } = attachmentOf(key, index);
    const head = a.content.slice(0, 40).toString('utf8');
    const res = await pgp.decrypt(head.includes('-----BEGIN') ? a.content.toString('utf8') : a.content);
    const outName = a.filename.replace(/\.(pgp|gpg|asc)$/i, '') || 'decrypted';
    const saved = await saveDialog(outName, res.data);
    return { saved, signatures: res.signatures };
  });

  handle('att:importKey', async (key, index) => {
    const { a } = attachmentOf(key, index);
    return importKeys(a.content);
  });

  handle('mail:importAutocrypt', async key => {
    const m = openMessages.get(key);
    if (!m || !m.view.autocryptKey) throw new Error('No Autocrypt key in this message');
    return importKeys(Buffer.from(m.view.autocryptKey, 'base64'));
  });

  /* =================================================================
   * 6. PGP KEY MANAGEMENT
   * ================================================================= */
  handle('pgp:list', () => pgp.listKeys());
  handle('pgp:generate', async opts => { const k = await pgp.generate(opts); if (cache.isOpen()) await cache.rewrapPgp(pgp); return k; });
  handle('pgp:importText', text => importKeys(text));
  handle('pgp:importFile', async () => {
    const r = await dialog.showOpenDialog(win, {
      properties: ['openFile', 'multiSelections'],
      filters: [{ name: 'PGP keys', extensions: ['asc', 'gpg', 'pgp', 'key', 'pub', 'txt'] }, { name: 'All files', extensions: ['*'] }]
    });
    if (r.canceled) return null;
    const total = { imported: [], updated: [], secret: [] };
    for (const f of r.filePaths) {
      const res = await importKeys(fs.readFileSync(f));
      total.imported.push(...res.imported); total.updated.push(...res.updated); total.secret.push(...res.secret);
    }
    return total;
  });
  handle('pgp:exportPublic', fp => saveDialog('0x' + fp.slice(-16) + '-public.asc', pgp.exportPublic(fp), [{ name: 'PGP key', extensions: ['asc'] }]));
  handle('pgp:copyPublic', fp => { clipboard.writeText(pgp.exportPublic(fp)); return true; });
  handle('pgp:exportPrivate', fp => saveDialog('0x' + fp.slice(-16) + '-SECRET.asc', pgp.exportPrivate(fp), [{ name: 'PGP key', extensions: ['asc'] }]));
  handle('pgp:exportRevocation', fp => saveDialog('0x' + fp.slice(-16) + '-revocation.asc', pgp.exportRevocation(fp), [{ name: 'Revocation certificate', extensions: ['asc', 'rev'] }]));
  handle('pgp:delete', async (fp, includePrivate) => { pgp.deleteKey(fp, { includePrivate }); contacts.forgetKey(fp); if (includePrivate && cache.isOpen()) await cache.rewrapPgp(pgp); return true; });
  handle('pgp:setTrust', (fp, trust) => { pgp.setTrust(fp, trust); return true; });
  handle('pgp:revoke', fp => pgp.revoke(fp));
  handle('pgp:unlock', (fp, pass, remember) => pgp.unlock(fp, pass, !!remember));
  // Remembered passphrases (1.0.2) — stored encrypted with Windows DPAPI
  handle('pgp:remember', (fp, pass) => pgp.rememberPassphrase(fp, pass));
  handle('pgp:forget', fp => { pgp.forgetPassphrase(fp); return true; });
  // 1.5.0: "Remember on all my devices" — passphrase travels in the encrypted sync vault
  handle('pgp:syncPassphrase', async (fp, passphrase) => {
    if (!cloud.connected()) throw new Error('Set up "Sync with my web server" first (Settings).');
    await pgp.syncPassphrase(fp, passphrase);
    return true;
  });
  handle('pgp:unsyncPassphrase', fp => { pgp.clearSyncedPassphrase(fp); return true; });
  handle('pgp:canRemember', () => pgp.canRemember());
  handle('pgp:lockAll', () => { pgp.lockAll(); return true; });
  handle('pgp:changePassphrase', (fp, oldP, newP) => pgp.changePassphrase(fp, oldP, newP));
  handle('pgp:recipientStatus', async emails => {
    const st = await pgp.recipientStatus(emails);
    for (const e of Object.keys(st)) {                 // 1.1.0: add contact + policy
      const c = contacts.byEmail(e);
      st[e].contact = c ? { id: c.id, name: c.name, encrypt: c.encrypt, sign: c.sign } : null;
    }
    return st;
  });
  handle('pgp:secretFor', async email => {
    const fp = await pgp.findSecretFor(email);
    return fp ? pgp.describe(pgp.publicKeys.get(fp)) : null;
  });
  handle('pgp:lookup', email => pgp.lookupOnline(email));
  handle('pgp:publish', fp => pgp.publishToKeyserver(fp));

  /* =================================================================
   * 6b. CONTACTS (1.1.0)
   * ================================================================= */
  const describeFp = async fp => { const k = fp && pgp.publicKeys.get(fp); return k ? pgp.describe(k) : null; };

  handle('contacts:list', async () => {
    const out = [];
    for (const c of contacts.all()) out.push({ ...c, key: await describeFp(c.keyFp) });
    return out;
  });
  handle('contacts:save', async c => {
    const saved = contacts.save(c);
    // no key yet? pick up a matching key already in the keyring
    if (!saved.keyFp) {
      for (const e of saved.emails) {
        const st = (await pgp.recipientStatus([e]))[e];
        if (st.ok && st.fingerprint) { contacts.pinKey(saved.id, st.fingerprint); break; }
      }
    }
    return { ...contacts.get(saved.id), key: await describeFp(contacts.get(saved.id).keyFp) };
  });
  handle('contacts:delete', id => { contacts.delete(id); return true; });
  handle('contacts:pinKey', (id, fp) => contacts.pinKey(id, fp || null));

  // keys in the keyring that match any of the contact's addresses (to choose from)
  handle('contacts:candidateKeys', async id => {
    const c = contacts.get(id);
    if (!c) return [];
    const out = [];
    for (const key of pgp.publicKeys.values()) {
      if (pgp._emailsOf(key).some(e => c.emails.includes(e))) out.push(await pgp.describe(key));
    }
    return out;
  });

  // paste/import a key and assign it to this contact
  handle('contacts:importKeyFor', async (id, text) => {
    const peek = await pgp.peekKey(text);
    await importKeys(text);
    contacts.pinKey(id, peek.fingerprint);
    return describeFp(peek.fingerprint);
  });

  // autocomplete: contacts first, then other addresses that have a key in the keyring
  handle('contacts:search', async q => {
    const res = contacts.search(q, 8).map(r => ({ ...r, hasKey: !!r.keyFp }));
    const seen = new Set(res.map(r => r.email));
    const ql = String(q || '').toLowerCase();
    if (ql.length >= 2) {
      for (const key of pgp.publicKeys.values()) {
        const uid = key.getUserIDs()[0] || '';
        for (const e of pgp._emailsOf(key)) {
          if (seen.has(e) || !(e.includes(ql) || uid.toLowerCase().includes(ql))) continue;
          seen.add(e);
          res.push({ contactId: null, name: (uid.match(/^(.*?)\s*</) || [])[1] || '', email: e, hasKey: true });
        }
      }
    }
    return res.slice(0, 10);
  });

  // act on the sender of an open message: add contact / assign or replace key
  handle('contacts:fromMessage', async (msgKey, action) => {
    const m = openMessages.get(msgKey);
    if (!m || !m.sender) throw new Error('Open the message first');
    const s = m.sender;
    let c = contacts.byEmail(s.email) || contacts.save({ name: s.name, emails: [s.email] });
    if (action !== 'contact-only' && s.candidateFp) {
      if (!pgp.publicKeys.has(s.candidateFp) && s.offeredArmored) await pgp.importKeys(s.offeredArmored);
      if (pgp.publicKeys.has(s.candidateFp)) c = contacts.pinKey(c.id, s.candidateFp);
    }
    m.sender = await senderKeyInfo(m.view);
    const { offeredArmored, ...pub } = m.sender;
    return pub;
  });

  /* =================================================================
   * 6c. DRAFTS (1.1.0)
   * ================================================================= */
  handle('drafts:folder', accId => mail.draftsFolder(accId));
  handle('drafts:save', async (accId, draft, prev) => {
    const acc = store.getAccount(accId);
    // a draft kept on this PC while offline (1.3.0)
    const prevLocal = prev && prev.folder === '__local__' ? prev.uid : null;
    if (prevLocal && uploadedLocalDrafts.has(prevLocal)) { prev = uploadedLocalDrafts.get(prevLocal); uploadedLocalDrafts.delete(prevLocal); }
    const saveLocal = () => {
      if (!cacheOn()) return undefined;
      const id = prevLocal || require('crypto').randomUUID();
      const q = cache.getQueue('drafts').filter(d => d.id !== id);
      q.push({ id, accId, draft, saved: new Date().toISOString(), summary: { to: draft.to, subject: draft.subject } });
      cache.saveQueue('drafts', q);
      return { folder: '__local__', uid: id, local: true, encrypted: true };
    };
    return netOr(accId, async () => {
      const built = await buildDraft(pgp, acc, draft);
      const res = await mail.saveDraft(accId, built.raw, { replaceUid: prev && prev.folder !== '__local__' ? prev.uid : null, messageId: built.messageId });
      if (prevLocal && cacheOn()) cache.saveQueue('drafts', cache.getQueue('drafts').filter(d => d.id !== prevLocal)); // now on the server
      return { ...res, encrypted: built.encrypted };
    }, saveLocal);
  });
  handle('drafts:delete', async (accId, folder, uid) => {
    if (folder === '__local__') {
      if (cacheOn()) cache.saveQueue('drafts', cache.getQueue('drafts').filter(d => d.id !== uid));
      const up = uploadedLocalDrafts.get(uid);
      if (up) { uploadedLocalDrafts.delete(uid); try { await mail.deleteDraft(up.accId, up.folder, up.uid); } catch { /* ignore */ } }
      return true;
    }
    return netOr(accId, () => mail.deleteDraft(accId, folder, uid), () => { throw offlineError('Deleting a server draft needs a connection.'); });
  });
  // reopen a draft that is kept on this PC
  handle('drafts:openLocal', id => {
    if (!cacheOn()) throw new Error('Offline mail is locked');
    const d = cache.getQueue('drafts').find(x => x.id === id);
    if (!d) throw new Error('Draft not found');
    const x = d.draft;
    const attachments = (x.attachments || []).map(a => a.path
      ? (fs.existsSync(a.path) ? { filename: path.basename(a.path), size: fs.statSync(a.path).size, content: fs.readFileSync(a.path).toString('base64') } : null)
      : { filename: a.filename, size: Buffer.from(a.content, 'base64').length, content: a.content, contentType: a.contentType }).filter(Boolean);
    return {
      accId: d.accId, folder: '__local__', uid: d.id, encrypted: true,
      to: x.to, cc: x.cc, bcc: x.bcc, subject: x.subject, text: x.text, html: x.html, attachments,
      meta: { format: x.html ? 'rich' : 'plain', encrypt: x.encrypt, sign: x.sign, hideSubject: x.hideSubject, attachPublicKey: x.attachPublicKey,
        inReplyTo: x.inReplyTo, references: x.references, replyToUid: x.replyToUid, replyFolder: x.replyFolder,
        fromAddress: x.fromAddress || null }   // 1.9.0
    };
  });
  handle('drafts:open', async (accId, folder, uid) => {
    const raw = await mail.getRaw(accId, folder, uid, { markSeen: false });
    return { ...(await readDraft(raw, pgp)), folder, uid };
  });

  /* =================================================================
   * 6d. KEY EXPIRY (1.1.0)
   * ================================================================= */
  handle('pgp:expiryWarnings', () => pgp.expiryWarnings(30));
  handle('pgp:extendExpiry', (fp, pass, years) => pgp.extendExpiry(fp, pass, years));

  /* =================================================================
   * 6e. APP LOCK (1.1.0)
   * ================================================================= */
  const lockPublic = () => {
    const c = lockCfg() || {};
    // 1.3.0: Windows Hello can't open the PIN-encrypted offline cache, so it's off while that's in use
    const helloBlocked = offlineCfg().enabled;
    return { enabled: lockEnabled(), locked: appLocked, hello: !!c.hello && !helloBlocked, helloBlocked, idleMinutes: Number(c.idleMinutes) || 0, platform: process.platform };
  };
  const unlockNow = () => { appLocked = false; lastActivity = Date.now(); lockLib.recordSuccess(); cloudSyncSoon(3000); return true; }; // 1.4.0: catch up on sync after unlocking

  handle('lock:status', () => lockPublic());
  handle('lock:helloAvailable', () => lockLib.helloAvailability());
  handle('lock:setup', ({ pin, hello, idleMinutes }) => {
    if (!/^\d{4,12}$/.test(String(pin || ''))) throw new Error('PIN must be 4 to 12 digits');
    const { salt, hash } = lockLib.hashPin(pin);
    store.setSettings({ appLock: { enabled: true, salt, hash, hello: !!hello, idleMinutes: Math.max(0, Number(idleMinutes) || 0) } });
    return lockPublic();
  });
  handle('lock:update', ({ hello, idleMinutes }) => {
    const c = lockCfg();
    if (!c || !c.enabled) throw new Error('App lock is off');
    if (hello && offlineCfg().enabled) throw new Error('Windows Hello can\'t be used while Offline mail is on — the offline copy is locked to your PIN.');
    store.setSettings({ appLock: { ...c, hello: !!hello, idleMinutes: Math.max(0, Number(idleMinutes) || 0) } });
    return lockPublic();
  });
  handle('lock:changePin', (oldPin, newPin) => {
    const c = lockCfg();
    if (!lockLib.checkPin(oldPin, c)) throw new Error('Current PIN is wrong');
    if (!/^\d{4,12}$/.test(String(newPin || ''))) throw new Error('PIN must be 4 to 12 digits');
    if (offlineCfg().enabled && String(newPin).length < 6) throw new Error('Offline mail is locked to your PIN: use at least 6 digits (8 or more recommended).');
    store.setSettings({ appLock: { ...c, ...lockLib.hashPin(newPin) } });
    if (cache.isOpen()) cache.rewrapPin(newPin); // 1.3.0: offline copy follows the new PIN
    return true;
  });
  handle('lock:disable', pin => {
    if (!lockLib.checkPin(pin, lockCfg())) throw new Error('PIN is wrong');
    if (cache.isOpen() && cache.outbox().length) throw new Error('There are unsent messages in the Outbox. Send or delete them first.');
    store.setSettings({ appLock: null });
    // 1.3.0: the offline copy is locked to the PIN — without a PIN it's removed
    if (cache.exists()) { cache.destroy(); store.setSettings({ offline: { ...offlineCfg(), enabled: false } }); }
    return lockPublic();
  });
  handle('lock:lockNow', () => { lockApp('locked by you'); return true; });
  handle('lock:activity', () => { lastActivity = Date.now(); return true; });

  handle('lock:unlockPin', async pin => {
    lockLib.attemptAllowed();
    if (!lockLib.checkPin(pin, lockCfg())) { lockLib.recordFailure(); throw new Error('Wrong PIN'); }
    await openCacheAfterUnlock({ pin }); // 1.3.0
    return unlockNow();
  });
  handle('lock:unlockHello', async () => {
    const c = lockCfg();
    if (offlineCfg().enabled) throw new Error('Enter your PIN — Offline mail is locked to it');
    if (!c || !c.hello) throw new Error('Windows Hello is not turned on for Sealpost');
    if (win && !win.isDestroyed()) win.focus();
    const r = await lockLib.helloVerify('Unlock Sealpost');
    if (!r.verified) throw new Error('Windows Hello: ' + r.result);
    return unlockNow();
  });
  // Forgot the PIN? Any of your PGP key passphrases also unlocks Sealpost.
  handle('lock:unlockPassphrase', async pass => {
    lockLib.attemptAllowed();
    if (!(await pgp.verifyAnyPassphrase(pass))) { lockLib.recordFailure(); throw new Error('That passphrase does not match any of your keys'); }
    await openCacheAfterUnlock({ passphrase: pass }); // 1.3.0
    return unlockNow();
  });

  /* =================================================================
   * 6f. INSTANT NEW MAIL (1.2.0)
   * ================================================================= */
  handle('push:status', () => mail.watchStatus());
  handle('app:reload', () => { if (win) win.webContents.reload(); return true; });
  handle('app:focus', () => { if (win) { if (win.isMinimized()) win.restore(); win.show(); win.focus(); } return true; });

  /* =================================================================
   * 6g. BACKUP & RESTORE (1.2.0)
   * ================================================================= */
  let pendingRestore = null; // { path, payload }

  handle('backup:create', async passphrase => {
    const { data, summary } = await backupLib.createBackup({ store, pgp, contacts, appVersion: process.env.SEALPOST_RUNNING_VERSION || app.getVersion(), passphrase });
    const day = new Date().toISOString().slice(0, 10);
    const r = await dialog.showSaveDialog(win, {
      title: 'Save Sealpost backup',
      defaultPath: path.join(app.getPath('documents'), `Sealpost-backup-${day}.sealbackup`),
      filters: [{ name: 'Sealpost backup', extensions: ['sealbackup'] }]
    });
    if (r.canceled || !r.filePath) return null;
    fs.writeFileSync(r.filePath, data);
    // read it straight back to prove the file is good before we call it done
    await backupLib.readBackup(fs.readFileSync(r.filePath), passphrase);
    store.setSettings({ lastBackup: new Date().toISOString() });
    return { path: r.filePath, summary };
  });

  handle('backup:pick', async () => {
    const r = await dialog.showOpenDialog(win, {
      title: 'Choose a Sealpost backup', properties: ['openFile'],
      filters: [{ name: 'Sealpost backup', extensions: ['sealbackup', 'gpg', 'pgp'] }, { name: 'All files', extensions: ['*'] }]
    });
    if (r.canceled || !r.filePaths[0]) return null;
    pendingRestore = { path: r.filePaths[0], payload: null };
    return { name: path.basename(r.filePaths[0]) };
  });

  handle('backup:read', async passphrase => {
    if (!pendingRestore) throw new Error('Choose a backup file first');
    pendingRestore.payload = await backupLib.readBackup(fs.readFileSync(pendingRestore.path), passphrase);
    return backupLib.summarize(pendingRestore.payload);
  });

  handle('backup:restore', async opts => {
    if (!pendingRestore || !pendingRestore.payload) throw new Error('Open the backup first');
    const result = await backupLib.restoreBackup(pendingRestore.payload, { store, pgp, contacts }, opts || {});
    pendingRestore = null;
    await mail.disconnectAll();
    applyPushSetting();
    return result;
  });

  /* =================================================================
   * 8. SYNC WITH MY WEB SERVER (1.4.0)
   *    The vault passphrase is only used here for a moment to derive
   *    keys; it is never stored.
   * ================================================================= */
  handle('cloud:status', () => cloud.status());
  handle('cloud:probe', server => cloud.probe(server));
  handle('cloud:connect', opts => cloud.connect({ ...opts, deviceName: (opts && opts.deviceName) || require('os').hostname() }));
  handle('cloud:syncNow', () => cloud.sync('manual'));
  handle('cloud:reauth', passphrase => cloud.reauth(passphrase));
  handle('cloud:changePassphrase', opts => cloud.changePassphrase(opts || {}));
  handle('cloud:devices', () => cloud.devices());
  handle('cloud:revoke', id => cloud.revoke(id));
  handle('cloud:disconnect', () => cloud.disconnect());

  /* =================================================================
   * 6h. OFFLINE MAIL + OUTBOX (1.3.0)
   * ================================================================= */
  const offlineStatus = () => {
    const cfg = offlineCfg();
    const open = cache.isOpen();
    const counts = open ? { outbox: cache.outbox().length, pending: cache.getQueue('pending').length, drafts: cache.getQueue('drafts').length } : {};
    return { ...cfg, exists: cache.exists(), open, usage: cache.exists() ? cache.usage().bytes : 0, syncing, lastSync,
      offlineAccounts: [...offlineAccounts], lockEnabled: lockEnabled(), ...counts };
  };
  handle('offline:status', () => offlineStatus());

  handle('offline:enable', async ({ pin, days, maxMsgMB, capMB }) => {
    if (!lockEnabled()) throw new Error('Turn on App lock first — offline mail is encrypted to your PIN.');
    if (!lockLib.checkPin(pin, lockCfg())) throw new Error('Wrong PIN');
    if (String(pin).length < 6) throw new Error('Your PIN is shorter than 6 digits. Change it to 6 or more (8+ recommended) first — it is what protects the offline copy.');
    await cache.create(String(pin), pgp);
    const c = lockCfg();
    if (c.hello) store.setSettings({ appLock: { ...c, hello: false } }); // Hello can't open a PIN-encrypted cache
    store.setSettings({ offline: { enabled: true, days: Number(days) || 30, maxMsgMB: Number(maxMsgMB) || 10, capMB: Number(capMB) || 500 } });
    scheduleSync(500);
    return offlineStatus();
  });

  handle('offline:update', ({ days, maxMsgMB, capMB }) => {
    store.setSettings({ offline: { ...offlineCfg(), days: Number(days) || 30, maxMsgMB: Number(maxMsgMB) || 10, capMB: Number(capMB) || 500 } });
    if (cacheOn()) { cache.enforceCap(offlineCfg().capMB * 1048576, store.listAccounts().map(a => a.id)); scheduleSync(1000); }
    return offlineStatus();
  });

  handle('offline:disable', () => {
    if (cache.isOpen() && cache.outbox().length) throw new Error('There are unsent messages in the Outbox. Send or delete them first.');
    cache.destroy();
    store.setSettings({ offline: { ...offlineCfg(), enabled: false } });
    return offlineStatus();
  });

  // remove saved mail but keep the Outbox, unsent changes and offline drafts
  handle('offline:clear', () => {
    if (!cacheOn()) throw new Error('Offline mail is not open');
    for (const a of store.listAccounts()) fs.rmSync(cache._accDir(a.id), { recursive: true, force: true });
    scheduleSync(2000);
    return offlineStatus();
  });

  handle('offline:syncNow', async () => { await flushQueues(); await runSync(); return offlineStatus(); });

  handle('outbox:list', () => {
    if (!cacheOn()) return { outbox: [], drafts: [] };
    return {
      outbox: cache.outbox().map(({ raw, envelope, ...o }) => ({ ...o, size: Math.round(raw.length * 0.75) })),
      drafts: cache.getQueue('drafts').map(d => ({ id: d.id, accId: d.accId, saved: d.saved, summary: d.summary, error: d.error }))
    };
  });
  handle('outbox:delete', id => { cache.saveQueue('outbox', cache.outbox().filter(o => o.id !== id)); return true; });
  handle('outbox:sendNow', async () => { await flushQueues(); return { waiting: cacheOn() ? cache.outbox().length : 0 }; });

  /* =================================================================
   * 7. PGP TOOLS (work on pasted text, e.g. for webmail or chat)
   * ================================================================= */
  handle('tools:encrypt', async ({ text, recipients, signWith }) => {
    const signerFp = signWith ? await pgp.findSecretFor(signWith) : null;
    if (signWith && !signerFp) throw new Error('No private key for ' + signWith);
    const armored = await pgp.encrypt({
      data: Buffer.from(text, 'utf8'),
      recipients: recipients.map(r => r.trim().toLowerCase()).filter(Boolean),
      signerFp,
      encryptToSelfFp: signerFp
    });
    return armored;
  });
  handle('tools:sign', async ({ text, signWith }) => {
    const fp = await pgp.findSecretFor(signWith);
    if (!fp) throw new Error('No private key for ' + signWith);
    return pgp.signCleartext({ text, signerFp: fp });
  });
  handle('tools:process', async text => {
    // auto-detect: encrypted block, signed block, or key block
    if (/-----BEGIN PGP MESSAGE-----/.test(text)) {
      const block = text.match(/-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/)[0];
      const r = await pgp.decrypt(block);
      return { kind: 'decrypted', text: r.data.toString('utf8'), signatures: r.signatures };
    }
    if (/-----BEGIN PGP SIGNED MESSAGE-----/.test(text)) {
      const r = await pgp.verifyCleartext(text.match(/-----BEGIN PGP SIGNED MESSAGE-----[\s\S]*?-----END PGP SIGNATURE-----/)[0]);
      return { kind: 'verified', text: r.text, signatures: r.signatures };
    }
    if (/-----BEGIN PGP (PUBLIC|PRIVATE) KEY BLOCK-----/.test(text)) {
      return { kind: 'imported', result: await importKeys(text) };
    }
    throw new Error('No PGP block found in the text');
  });
}
