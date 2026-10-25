/* =====================================================================
 * Sealpost — preload.js
 * The only bridge between the UI and the main process. Exposes a
 * fixed list of calls as window.api.<name>(...). Every call resolves to
 * { ok:true, data } or { ok:false, error, code, ... }.
 * ===================================================================== */
const { contextBridge, ipcRenderer } = require('electron');

const channels = [
  'settings:get', 'settings:set',
  'accounts:list', 'accounts:presets', 'accounts:save', 'accounts:delete', 'accounts:test',
  'mail:folders', 'mail:list', 'mail:open', 'mail:source', 'mail:flag', 'mail:move', 'mail:delete',
  'mail:createFolder', 'mail:send', 'mail:importAutocrypt',
  'app:info', 'app:installUpdate', 'app:restart',
  'dialog:pickFiles', 'shell:openExternal', 'clipboard:write', 'clipboard:read',
  'att:save', 'att:open', 'att:decrypt', 'att:importKey',
  'pgp:list', 'pgp:generate', 'pgp:importText', 'pgp:importFile', 'pgp:exportPublic', 'pgp:copyPublic',
  'pgp:exportPrivate', 'pgp:exportRevocation', 'pgp:delete', 'pgp:setTrust', 'pgp:revoke', 'pgp:unlock',
  'pgp:lockAll', 'pgp:remember', 'pgp:forget', 'pgp:canRemember', 'pgp:changePassphrase', 'pgp:recipientStatus', 'pgp:secretFor', 'pgp:lookup', 'pgp:publish',
  'tools:encrypt', 'tools:sign', 'tools:process',
  // 1.1.0
  'contacts:list', 'contacts:save', 'contacts:delete', 'contacts:pinKey', 'contacts:candidateKeys', 'contacts:importKeyFor',
  'contacts:search', 'contacts:fromMessage',
  'drafts:folder', 'drafts:save', 'drafts:delete', 'drafts:open',
  'pgp:expiryWarnings', 'pgp:extendExpiry',
  'lock:status', 'lock:helloAvailable', 'lock:setup', 'lock:update', 'lock:changePin', 'lock:disable', 'lock:lockNow',
  'lock:activity', 'lock:unlockPin', 'lock:unlockHello', 'lock:unlockPassphrase',
  // 1.2.0
  'push:status', 'app:focus', 'app:reload', 'backup:create', 'backup:pick', 'backup:read', 'backup:restore',
  // 1.3.0
  'offline:status', 'offline:enable', 'offline:update', 'offline:disable', 'offline:clear', 'offline:syncNow',
  'outbox:list', 'outbox:delete', 'outbox:sendNow', 'drafts:openLocal',
  // 1.4.0 sync with my web server
  'cloud:status', 'cloud:probe', 'cloud:connect', 'cloud:syncNow', 'cloud:reauth', 'cloud:changePassphrase',
  'cloud:devices', 'cloud:revoke', 'cloud:disconnect',
  // 1.5.0
  'pgp:syncPassphrase', 'pgp:unsyncPassphrase',
  // 1.6.0
  'mail:markFolderRead',
  // 1.9.2
  'mail:foldersCached', 'mail:listCached',
  // 1.10.0
  'mail:renameFolder', 'mail:deleteFolder', 'accounts:setPrefs', 'mail:listUnified', 'mail:listUnifiedCached',
  // 1.12.0 updates from GitHub
  'app:checkUpdate', 'app:downloadUpdate', 'app:releasesPage'
];

const api = {};
for (const ch of channels) {
  // 'mail:open' -> api.mailOpen
  const name = ch.replace(/:(\w)/, (_, c) => c.toUpperCase());
  api[name] = (...args) => ipcRenderer.invoke(ch, ...args);
}

// 1.2.0: events pushed from the main process (new mail, connection status)
api.onEvent = cb => { ipcRenderer.on('sealpost:event', (_e, msg) => cb(msg)); };

// 1.8.0: which OS Sealpost runs on ('win32' | 'linux' | 'darwin') — the
// screens word a few things differently on Linux (no "Windows login" etc.)
api.platform = process.platform;
contextBridge.exposeInMainWorld('api', api);
