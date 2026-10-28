/* =====================================================================
 * Sealpost Web — vault.js
 * ---------------------------------------------------------------------
 * Signing in and reading your encrypted vault, entirely in the browser.
 * Uses exactly the same scheme as Sealpost on your PC (sync.js):
 *   master   = PBKDF2-SHA256(passphrase, "sealpost:" + username, iter)
 *   loginKey = HKDF(master, "sealpost-auth")  -> sent to the server
 *   wrapKey  = HKDF(master, "sealpost-wrap")  -> opens the vault key
 *   items    = AES-256-GCM, "v1." + base64(iv | ciphertext | tag),
 *              item id as associated data
 * The passphrase and the vault key never leave this browser tab.
 *
 * Sections:
 *   1. Small byte helpers
 *   2. Key derivation + item decryption (Web Crypto)
 *   3. Talking to api.php / mail.php
 *   4. Session (kept only for this tab — closing it signs you out)
 *   5. Sign in / sign out
 *   6. Loading the vault (accounts, contacts, keys, settings)
 *   7. Saving changes made on the web back to the vault (1.2.0)
 *   8. PIN unlock for an iPhone / home-screen app (1.5.0)
 *      + Face ID data kept with it (1.6.0, see faceid.js)
 * ===================================================================== */

/* =================================================================
 * 1. BYTE HELPERS
 * ================================================================= */
const te = new TextEncoder();
const td = new TextDecoder();

export function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToB64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

const fromHex = h => new Uint8Array(String(h).match(/../g).map(x => parseInt(x, 16)));
const hex = bytes => [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');

/* =================================================================
 * 2. KEY DERIVATION + DECRYPTION
 * ================================================================= */
export async function deriveKeys(passphrase, username, kdf) {
  if (!kdf || kdf.alg !== 'pbkdf2-sha256') throw new Error('This vault uses a key setting this page does not know.');
  const salt = te.encode('sealpost:' + String(username).trim().toLowerCase());
  const passKey = await crypto.subtle.importKey('raw', te.encode(String(passphrase).normalize('NFC')), 'PBKDF2', false, ['deriveBits']);
  const master = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: kdf.iter }, passKey, 256);
  const hk = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveBits']);
  const hkdf = info => crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: te.encode(info) }, hk, 256);
  const authKey = hex(new Uint8Array(await hkdf('sealpost-auth')));
  const wrapKey = await crypto.subtle.importKey('raw', await hkdf('sealpost-wrap'), 'AES-GCM', false, ['decrypt']);
  return { authKey, wrapKey };
}

/** "v1." + base64(iv[12] | ciphertext | tag[16]) -> Uint8Array */
/** Encrypt for the vault: same format Sealpost on your PC writes. */
export async function seal(key, bytes, aad) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: te.encode(aad), tagLength: 128 }, key, bytes));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv); out.set(ct, 12);
  return 'v1.' + bytesToB64(out);
}

export async function unseal(key, blob, aad) {
  if (typeof blob !== 'string' || !blob.startsWith('v1.')) throw new Error('Unknown item format');
  const raw = b64ToBytes(blob.slice(3));
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: raw.subarray(0, 12), additionalData: te.encode(aad), tagLength: 128 },
    key, raw.subarray(12)
  );
  return new Uint8Array(plain);
}

/* =================================================================
 * 3. SERVER CALLS
 * ================================================================= */
export class ServerError extends Error {
  constructor(message, code, status) { super(message); this.code = code; this.status = status; }
}

let session = null;          // { token, username, vk (base64), deviceId }
let onSignedOut = () => {};
export const setSignedOutHandler = fn => { onSignedOut = fn; };

async function post(file, action, body, { raw = false } = {}) {
  const headers = { 'Content-Type': 'application/json', 'Accept': 'application/json' };
  if (session && session.token) headers['X-Sealpost-Token'] = session.token;
  let res;
  try {
    res = await fetch(`${file}?action=${encodeURIComponent(action)}`, { method: 'POST', headers, body: JSON.stringify(body || {}), credentials: 'omit', cache: 'no-store' });
  } catch {
    throw new ServerError('Can\'t reach your server. Check your connection.', 'network', 0);
  }
  const type = res.headers.get('content-type') || '';
  if (raw && res.ok && !type.includes('json')) {
    return { bytes: new Uint8Array(await res.arrayBuffer()), flags: (res.headers.get('x-sealpost-flags') || '').split(' ').filter(Boolean) };
  }
  let json;
  try { json = await res.json(); } catch { throw new ServerError('The server sent an unexpected reply (HTTP ' + res.status + ').', 'bad_reply', res.status); }
  if (!json.ok) {
    if (json.error === 'not_signed_in' && session) { clearSession(); onSignedOut(json.message); }
    throw new ServerError(json.message || json.error, json.error, res.status);
  }
  return json;
}

export const api = (action, body) => post('api.php', action, body);
export { post };
export const mail = (action, body, opts) => post('mail.php', action, body, opts);

/* =================================================================
 * 4. SESSION — sessionStorage: this tab only, gone when it closes
 * ================================================================= */
const KEY = 'sealpost-web-session';

export function loadSession() {
  try { session = JSON.parse(sessionStorage.getItem(KEY) || 'null'); } catch { session = null; }
  return session;
}

function saveSession() {
  try { sessionStorage.setItem(KEY, JSON.stringify(session)); } catch { /* private mode: stays in memory */ }
}

export function clearSession() {
  session = null;
  try { sessionStorage.removeItem(KEY); } catch { /* ignore */ }
}

export const currentUser = () => session && session.username;
export const token = () => session && session.token;

/* =================================================================
 * 5. SIGN IN / SIGN OUT
 * ================================================================= */
function deviceName() {
  const ua = navigator.userAgent;
  const browser = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  const os = /Windows/.test(ua) ? 'Windows' : /iPhone|iPad/.test(ua) ? 'iOS' : /Android/.test(ua) ? 'Android' : /Mac OS X/.test(ua) ? 'Mac' : /Linux/.test(ua) ? 'Linux' : '';
  // 1.5.0: the home-screen app shows up under Devices as "Sealpost app · iPhone"
  const standalone = navigator.standalone === true || (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches);
  if (standalone) return `Sealpost app · ${/iPad/.test(ua) ? 'iPad' : /iPhone/.test(ua) ? 'iPhone' : os || browser}`;
  return `Sealpost Web · ${browser}${os ? ' on ' + os : ''}`;
}

export async function signIn(username, passphrase) {
  username = String(username || '').trim().toLowerCase();
  const pre = await api('prelogin', { username });
  const { authKey, wrapKey } = await deriveKeys(passphrase, username, pre.kdf);
  session = null;
  // 1.5.0: if this phone had PIN unlock before, its old registration is replaced
  const old = pinDevice();
  const r = await api('login', { username, authKey, deviceName: deviceName(), kind: 'web', replaceDevice: old ? old.deviceId : undefined });
  if (old) forgetPinDevice();
  let vk;
  try { vk = await unseal(wrapKey, r.wrappedKey, 'sealpost-vault-key'); }
  catch { throw new Error('Signed in, but the vault key could not be opened with this passphrase.'); }
  session = { token: r.token, username: r.username, deviceId: r.deviceId, vk: bytesToB64(vk), keyVersion: r.keyVersion };
  saveSession();
  return session;
}

export async function signOut() {
  if (session) { try { await api('logout', {}); } catch { /* already gone */ } }
  clearSession();
}

/* =================================================================
 * 6. LOADING THE VAULT
 *    Returns { accounts, contacts, keys, settings, seq }.
 *    refresh(prev) only fetches what changed since prev.seq.
 * ================================================================= */
async function vaultKey() {
  return crypto.subtle.importKey('raw', b64ToBytes(session.vk), 'AES-GCM', false, ['decrypt', 'encrypt']);
}

/*  items: Map id -> envelope { v, id, type, updated, device, data }
 *  seqs:  Map id -> server sequence number (deleted items too — needed
 *         as the "based on" number when saving them again)            */
export async function loadVault(prev = null) {
  const vk = await vaultKey();
  const items = new Map(prev ? prev.items : []);
  const seqs = new Map(prev ? prev.seqs : []);
  let since = prev ? prev.seq : 0;
  let keyVersion = session.keyVersion;
  for (;;) {
    const r = await api('pull', { since, limit: 500 });
    keyVersion = r.keyVersion;
    for (const it of r.items) {
      since = Math.max(since, it.seq);
      seqs.set(it.id, it.seq);
      if (it.deleted || !it.data) { items.delete(it.id); continue; }
      try {
        const env = JSON.parse(td.decode(await unseal(vk, it.data, it.id)));
        if (env.id === it.id) items.set(it.id, env);
      } catch { /* damaged item: skip */ }
    }
    if (!r.more) break;
  }
  if (keyVersion !== session.keyVersion) {
    // the passphrase was changed on another device: the vault key itself is unchanged, so carry on
    session.keyVersion = keyVersion; saveSession();
  }
  return derive({ items, seqs, seq: since });
}

/** 1.11.2: accounts in the order you arranged them (settings.accountOrder, a list of
 *  account ids). Accounts not in the list keep their place after the others.
 *  Same function in Sealpost on your PC (store.js) — keep both identical. */
export function orderAccounts(accounts, order) {
  const pos = new Map((Array.isArray(order) ? order : []).map((id, i) => [String(id), i]));
  const at = (a, i) => (pos.has(a.id) ? pos.get(a.id) : pos.size + i);
  return accounts.map((a, i) => [at(a, i), a]).sort((x, y) => x[0] - y[0]).map(x => x[1]);
}

/** Lists the app works with, from the raw items. */
function derive(v) {
  const of = type => [...v.items.values()].filter(e => e.type === type).map(e => e.data);
  const settingsEnv = v.items.get('settings:main');
  return {
    ...v,
    accounts: orderAccounts(of('account'), settingsEnv && settingsEnv.data && settingsEnv.data.accountOrder),   // 1.11.2
    contacts: of('contact'),
    keys: [...v.items.entries()].filter(([id]) => id.startsWith('key:')).map(([id, e]) => ({ fingerprint: id.slice(4), ...e.data })),
    passphrases: new Map(of('passphrase').filter(p => p && p.fingerprint && p.passphrase).map(p => [p.fingerprint.toUpperCase(), p.passphrase])),
    settings: settingsEnv ? settingsEnv.data : {}
  };
}

/* =================================================================
 * 7. SAVING CHANGES — [{ id: 'contact:…', type: 'contact', data | null }]
 *    null data = delete. Each item says which version it was based on;
 *    if another device changed it meanwhile, the server says so and we
 *    save again on top of that (the change you just made wins).
 *    Returns the updated vault.
 * ================================================================= */
export async function saveItems(v, changes) {
  const vk = await vaultKey();
  const items = new Map(v.items), seqs = new Map(v.seqs);
  let pending = changes;
  for (let round = 0; round < 3 && pending.length; round++) {
    const out = [];
    for (const c of pending) {
      const env = { v: 1, id: c.id, type: c.type, updated: Date.now(), device: 'Sealpost Web', data: c.data };
      out.push({ id: c.id, base: seqs.get(c.id) || 0, deleted: c.data == null, data: c.data == null ? undefined : await seal(vk, te.encode(JSON.stringify(env)), c.id), _env: env });
    }
    // the server takes up to 500 items per request
    const results = [];
    for (let i = 0; i < out.length; i += 200) {
      const r = await api('push', { keyVersion: session.keyVersion, items: out.slice(i, i + 200).map(({ _env, ...x }) => x) });
      results.push(...r.results);
    }
    const retry = [];
    for (const res of results) {
      const sent = out.find(o => o.id === res.id);
      const change = pending.find(p => p.id === res.id);
      if (res.ok) {
        seqs.set(res.id, res.seq);
        if (sent.deleted) items.delete(res.id); else items.set(res.id, sent._env);
      } else if (res.conflict) {
        seqs.set(res.id, res.server.seq);
        retry.push(change);
      } else throw new Error('The vault refused a change (' + (res.error || 'unknown') + ')');
    }
    pending = retry;
  }
  if (pending.length) throw new Error('Could not save — the item keeps changing on another device. Try again.');
  return derive({ items, seqs, seq: v.seq });
}

/** The connection details mail.php needs for one account. */
export function imapDetails(acc) {
  return {
    host: acc.imapHost, port: acc.imapPort, security: acc.imapSecurity,
    username: acc.username || acc.email, password: acc.password, allowSelfSigned: !!acc.allowSelfSigned
  };
}

/* =================================================================
 * 8. PIN UNLOCK (1.5.0) — for the iPhone home-screen app
 * -----------------------------------------------------------------
 *  Kept on the phone (localStorage 'sealpost-device'):
 *    { deviceId, username, salt, iter, wrapped }
 *  wrapped = the vault key, encrypted with
 *    HKDF( PBKDF2(PIN, salt)  +  secret held only by the server )
 *  The server hands out its secret only for the right PIN proof
 *  (pinAuth = HKDF(PBKDF2(PIN, salt), "sealpost-pin-auth")) and
 *  forgets this device after 5 wrong PINs. So a stolen phone alone
 *  can't open the vault, and the server alone can't either.
 * ================================================================= */
const DEVICE_KEY = 'sealpost-device';
const PIN_ITER = 210000;

export function pinDevice() {
  try {
    const d = JSON.parse(localStorage.getItem(DEVICE_KEY) || 'null');
    return d && d.deviceId && d.wrapped && d.salt ? d : null;
  } catch { return null; }
}

export function forgetPinDevice() {
  try { localStorage.removeItem(DEVICE_KEY); } catch { /* ignore */ }
}

/** Is PIN unlock set up for the device that is signed in right now? */
export const pinActive = () => { const d = pinDevice(); return !!(d && session && d.deviceId === session.deviceId); };

async function pinKeys(pin, salt, iter) {
  const pk = await crypto.subtle.importKey('raw', te.encode(String(pin)), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, pk, 256));
  const hk = await crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveBits']);
  const pinAuth = hex(new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: te.encode('sealpost-pin-auth') }, hk, 256)));
  return { bits, pinAuth };
}

async function pinWrapKey(bits, secretHex) {
  const secret = fromHex(secretHex);
  const both = new Uint8Array(bits.length + secret.length);
  both.set(bits); both.set(secret, bits.length);
  const hk = await crypto.subtle.importKey('raw', both, 'HKDF', false, ['deriveBits']);
  const raw = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: te.encode('sealpost-pin-wrap') }, hk, 256);
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

/** Turn on PIN unlock for this (signed-in) device. */
export async function setupPin(pin) {
  if (!session) throw new Error('Not signed in.');
  if (!/^\d{6,12}$/.test(String(pin))) throw new Error('Use 6 to 12 digits.');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const { bits, pinAuth } = await pinKeys(pin, salt, PIN_ITER);
  const r = await api('pinSetup', { pinAuth });
  const wk = await pinWrapKey(bits, r.secret);
  const wrapped = await seal(wk, b64ToBytes(session.vk), 'sealpost-pin-vault-key');
  const d = { v: 1, deviceId: r.deviceId, username: session.username, salt: bytesToB64(salt), iter: PIN_ITER, wrapped };
  try { localStorage.setItem(DEVICE_KEY, JSON.stringify(d)); }
  catch { await api('pinRemove', {}).catch(() => {}); throw new Error('This browser won\'t store data (private browsing?), so PIN unlock can\'t be used here.'); }
  session.deviceId = r.deviceId; saveSession();
}

/** Open the vault with the PIN. Wrong PIN -> ServerError code 'bad_pin' (+ triesLeft). */
export async function unlockWithPin(pin) {
  const d = pinDevice();
  if (!d) throw new ServerError('PIN unlock isn\'t set up here.', 'pin_reset', 401);
  const { bits, pinAuth } = await pinKeys(pin, b64ToBytes(d.salt), d.iter || PIN_ITER);
  session = null;
  let r;
  try { r = await api('pinUnlock', { deviceId: d.deviceId, pinAuth }); }
  catch (e) { if (e.code === 'pin_reset') forgetPinDevice(); throw e; }
  let vk;
  try { vk = await unseal(await pinWrapKey(bits, r.secret), d.wrapped, 'sealpost-pin-vault-key'); }
  catch {
    forgetPinDevice();
    throw new ServerError('The PIN data on this phone is damaged. Sign in with your vault passphrase.', 'pin_reset', 401);
  }
  session = { token: r.token, username: r.username, deviceId: d.deviceId, vk: bytesToB64(vk), keyVersion: r.keyVersion };
  saveSession();
  return session;
}

/** 1.6.0: keep / drop the Face ID data ({ credId, salt, wrapped }) for this phone's PIN. */
export function setDeviceFace(face) {
  const d = pinDevice();
  if (!d) return;
  if (face) d.face = face; else delete d.face;
  try { localStorage.setItem(DEVICE_KEY, JSON.stringify(d)); } catch { /* ignore */ }
}

/** Turn PIN unlock off (the device stays signed in for now). */
export async function removePin() {
  if (session) await api('pinRemove', {});
  forgetPinDevice();
}

/** Lock: end this session but keep the device, so the PIN opens it again. */
export async function lock() {
  if (session) { try { await api('lock', {}); } catch { /* already locked */ } }
  clearSession();
}

/** Sign out completely: also forgets PIN unlock on this phone. */
export async function signOutEverywhere() {
  await signOut();
  forgetPinDevice();
}
