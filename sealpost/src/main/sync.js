/* =====================================================================
 * Sealpost — sync.js   (added 1.4.0)
 * ---------------------------------------------------------------------
 * "Sync with my web server": keeps accounts, contacts, PGP keys and
 * settings the same on every Sealpost that's connected to your own
 * Sealpost Sync server (the PHP files on your website).
 *
 * ZERO-KNOWLEDGE DESIGN
 *   One vault passphrase, chosen by you, never leaves this PC.
 *     master   = PBKDF2-SHA256(passphrase, "sealpost:" + username, 600 000)
 *     loginKey = HKDF(master, "sealpost-auth")   -> sent to the server, which
 *                                                   stores only an Argon2id hash
 *     wrapKey  = HKDF(master, "sealpost-wrap")   -> never sent anywhere
 *   A random 256-bit VAULT KEY encrypts every item (AES-256-GCM, the item
 *   id is bound in as associated data so items can't be swapped). The
 *   server keeps the vault key only "wrapped" (encrypted) with wrapKey.
 *   On this PC the vault key and the device token are kept protected by
 *   your Windows login (DPAPI), so syncing never asks for the passphrase
 *   — except after the passphrase was changed on another device.
 *   All of this uses only PBKDF2 / HKDF / AES-GCM so the web version
 *   (stage 2) can do exactly the same in the browser with Web Crypto.
 *
 * WHAT SYNCS
 *   settings:main     settings, minus per-PC ones (app lock PIN, offline
 *                     cache, last backup date, sync itself)
 *   account:<id>      mail accounts INCLUDING passwords (encrypted)
 *   contact:<id>      contacts and their assigned keys
 *   key:<FINGERPRINT> public key, secret key (still protected by its own
 *                     passphrase), revocation certificate, trust level
 *   passphrase:<FP>   (1.5.0) a key passphrase you chose to "Remember on all
 *                     my devices" — only for keys where you ticked that box
 *   Not synced: "remember passphrase" (locked to this Windows login),
 *   messages (they live on the mail server), the offline cache.
 *
 * HOW CHANGES ARE FOUND
 *   After every sync we remember, per item, the server sequence number
 *   and a SHA-256 of how the item looked here. Next time: a different
 *   hash = changed here; a newer sequence number on the server = changed
 *   elsewhere. Both = conflict (see section 6).
 *
 * Sections:
 *   1. Crypto helpers (key derivation, item encryption)
 *   2. Saved sync state (sync.json)
 *   3. Talking to the server
 *   4. Reading this PC's data as sync items
 *   5. Applying items from the server
 *   6. Conflicts
 *   7. The sync run (pull, apply, push)
 *   8. Connect / disconnect / passphrase / devices
 * ===================================================================== */

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { promisify } = require('util');
const pbkdf2 = promisify(crypto.pbkdf2);

const API_VERSION = 1;
const DEFAULT_KDF = { alg: 'pbkdf2-sha256', iter: 600000 };
const WRAP_AAD = 'sealpost-vault-key';
// settings that belong to this PC only
const LOCAL_SETTINGS = ['appLock', 'offline', 'lastBackup', 'shortcutIcon', 'sync'];
// order in which items from the server are applied (keys before the contacts that point at them)
const TYPE_ORDER = { key: 0, passphrase: 1, contact: 2, account: 3, settings: 4 };

/* =================================================================
 * 1. CRYPTO HELPERS
 * ================================================================= */
async function deriveKeys(passphrase, username, kdf = DEFAULT_KDF) {
  if (!kdf || kdf.alg !== 'pbkdf2-sha256') throw new Error('This server uses a key setting Sealpost doesn\'t know. Update Sealpost.');
  const salt = 'sealpost:' + String(username).trim().toLowerCase();
  const master = await pbkdf2(Buffer.from(String(passphrase).normalize('NFC'), 'utf8'), Buffer.from(salt, 'utf8'), kdf.iter, 32, 'sha256');
  const authKey = Buffer.from(crypto.hkdfSync('sha256', master, Buffer.alloc(0), 'sealpost-auth', 32)).toString('hex');
  const wrapKey = Buffer.from(crypto.hkdfSync('sha256', master, Buffer.alloc(0), 'sealpost-wrap', 32));
  master.fill(0);
  return { authKey, wrapKey };
}

/** AES-256-GCM: "v1." + base64(iv[12] | ciphertext | tag[16]) */
function seal(key, plain, aad) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(Buffer.from(aad, 'utf8'));
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return 'v1.' + Buffer.concat([iv, ct, c.getAuthTag()]).toString('base64');
}

function unseal(key, blob, aad) {
  if (typeof blob !== 'string' || !blob.startsWith('v1.')) throw new Error('Unknown item format');
  const raw = Buffer.from(blob.slice(3), 'base64');
  if (raw.length < 29) throw new Error('Item is damaged');
  const d = crypto.createDecipheriv('aes-256-gcm', key, raw.subarray(0, 12));
  d.setAAD(Buffer.from(aad, 'utf8'));
  d.setAuthTag(raw.subarray(raw.length - 16));
  return Buffer.concat([d.update(raw.subarray(12, raw.length - 16)), d.final()]);
}

/** JSON with sorted keys, so the same content always gives the same hash. */
function stable(v) {
  if (Array.isArray(v)) return '[' + v.map(stable).join(',') + ']';
  if (v && typeof v === 'object') return '{' + Object.keys(v).sort().filter(k => v[k] !== undefined).map(k => JSON.stringify(k) + ':' + stable(v[k])).join(',') + '}';
  return JSON.stringify(v === undefined ? null : v);
}
const hashOf = data => (data == null ? null : crypto.createHash('sha256').update(stable(data)).digest('hex'));

/** "example.com/sealpost" -> "https://example.com/sealpost/api.php" */
function normalizeServer(input) {
  let s = String(input || '').trim();
  if (!s) throw new Error('Enter your server address');
  if (!/^https?:\/\//i.test(s)) s = 'https://' + s;
  let u;
  try { u = new URL(s); } catch { throw new Error('That server address isn\'t valid'); }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  if (u.protocol !== 'https:' && !local) throw new Error('The server address must start with https://');
  u.search = ''; u.hash = '';
  if (!/\.php$/i.test(u.pathname)) u.pathname = u.pathname.replace(/\/?$/, '/') + 'api.php';
  return u.toString();
}

/* =================================================================
 * SYNC SERVICE
 * ================================================================= */
class SyncService {
  /**
   * @param o.dataDir   userData folder
   * @param o.store     Store (accounts + settings)
   * @param o.pgp       PgpEngine
   * @param o.contacts  ContactStore
   * @param o.secure    { encrypt, decrypt } (DPAPI) or null in tests
   * @param o.onEvent   (type, data) => void — progress / results for the window
   * @param o.onApplied (changes) => void    — main.js reacts (restart push, etc.)
   * @param o.fetch     fetch implementation (tests may pass their own)
   */
  constructor(o) {
    Object.assign(this, { store: o.store, pgp: o.pgp, contacts: o.contacts, secure: o.secure || null });
    this.file = path.join(o.dataDir, 'sync.json');
    this.quarantineDir = path.join(o.dataDir, 'keyring', 'removed-by-sync');
    this.onEvent = o.onEvent || (() => {});
    this.onApplied = o.onApplied || (() => {});
    this.fetch = o.fetch || ((...a) => fetch(...a));
    this.appVersion = o.appVersion || '';
    this.running = null;          // promise of the sync in progress
    this.again = false;           // another change arrived while syncing
    this.lastLocalChange = 0;     // when this PC last changed something (for conflicts)
    this.state = this._load();
  }

  /* =================================================================
   * 2. SAVED SYNC STATE (sync.json)
   *    { server, username, deviceId, deviceName, token*, vaultKey*,
   *      keyVersion, seq, items: { id: { seq, hash } }, lastSync,
   *      lastError, needs }        (* = protected by Windows login)
   * ================================================================= */
  _load() {
    try { const s = JSON.parse(fs.readFileSync(this.file, 'utf8')); if (s && s.server) return s; } catch { /* none */ }
    return null;
  }

  _save() {
    if (!this.state) { try { fs.unlinkSync(this.file); } catch { /* gone */ } return; }
    const tmp = this.file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(this.state, null, 1));
    fs.renameSync(tmp, this.file);
  }

  _protect(buf) {
    const s = Buffer.from(buf).toString('base64');
    return this.secure ? 'enc:' + this.secure.encrypt(s) : 'b64:' + s;
  }

  _unprotect(v) {
    if (!v) return null;
    if (v.startsWith('enc:') && this.secure) return Buffer.from(this.secure.decrypt(v.slice(4)), 'base64');
    if (v.startsWith('b64:')) return Buffer.from(v.slice(4), 'base64');
    return null;
  }

  _token() { const b = this._unprotect(this.state && this.state.token); return b ? b.toString('utf8') : null; }
  _vaultKey() { return this._unprotect(this.state && this.state.vaultKey); }

  connected() { return !!(this.state && this.state.token && this.state.vaultKey); }

  status() {
    const s = this.state;
    if (!s) return { connected: false };
    return {
      connected: true,
      server: s.server.replace(/api\.php$/i, ''),
      username: s.username,
      deviceName: s.deviceName,
      lastSync: s.lastSync || null,
      lastError: s.lastError || null,
      needs: s.needs || null,         // 'passphrase' | 'signin' | null
      items: Object.values(s.items || {}).filter(i => i.hash).length,
      running: !!this.running
    };
  }

  /** main.js calls this whenever accounts / contacts / keys / settings change. */
  noteLocalChange() { this.lastLocalChange = Date.now(); }

  /* =================================================================
   * 3. TALKING TO THE SERVER
   * ================================================================= */
  async _api(action, body, { server, auth = true, timeout = 30000 } = {}) {
    const url = (server || this.state.server) + '?action=' + encodeURIComponent(action);
    const headers = { 'Content-Type': 'application/json', 'Accept': 'application/json', 'User-Agent': 'Sealpost/' + this.appVersion };
    if (auth) headers['X-Sealpost-Token'] = this._token() || '';
    let res, text;
    try {
      res = await this.fetch(url, {
        method: action === 'ping' ? 'GET' : 'POST',
        headers,
        body: action === 'ping' ? undefined : JSON.stringify(body || {}),
        signal: AbortSignal.timeout(timeout),
        redirect: 'error'
      });
      text = await res.text();
    } catch (e) {
      const err = new Error('Can\'t reach the sync server (' + (e.cause && e.cause.code ? e.cause.code : e.name === 'TimeoutError' ? 'timed out' : e.message) + ')');
      err.code = 'NETWORK';
      throw err;
    }
    let json;
    try { json = JSON.parse(text); } catch {
      const err = new Error(res.status === 404 ? 'No Sealpost sync server at that address' : 'The server sent an unexpected reply (HTTP ' + res.status + ')');
      err.code = 'BAD_SERVER';
      throw err;
    }
    if (!json.ok) {
      const err = new Error(json.message || json.error || 'Server error');
      err.code = json.error || 'SERVER';
      err.status = res.status;
      throw err;
    }
    return json;
  }

  /* =================================================================
   * 4. THIS PC'S DATA AS SYNC ITEMS
   *    Returns Map id -> { type, data }
   * ================================================================= */
  _syncedSettings() {
    const s = { ...this.store.getSettings() };
    for (const k of LOCAL_SETTINGS) delete s[k];
    return s;
  }

  _keyData(fp) {
    const pub = this.pgp.publicKeys.get(fp);
    if (!pub) return null;
    const priv = this.pgp.privateKeys.get(fp);
    const revFile = path.join(this.pgp.privDir, fp + '.rev');
    return {
      public: pub.armor(),
      secret: priv ? priv.armor() : null,
      revocation: priv && fs.existsSync(revFile) ? fs.readFileSync(revFile, 'utf8') : null,
      trust: (this.pgp.meta[fp] && this.pgp.meta[fp].trust) || null
    };
  }

  _passData(fp) {
    const p = this.pgp.getSyncedPassphrase(fp);
    return p ? { fingerprint: fp, passphrase: p } : null;
  }

  _accountData(id) {
    try {
      const a = this.store.getAccount(id);
      return { ...a };
    } catch { return null; }
  }

  async collectLocal() {
    const out = new Map();
    out.set('settings:main', { type: 'settings', data: this._syncedSettings() });
    for (const a of this.store.data.accounts) {
      const d = this._accountData(a.id);
      if (d) out.set('account:' + a.id, { type: 'account', data: d });
    }
    for (const c of this.contacts.list) out.set('contact:' + c.id, { type: 'contact', data: { ...c } });
    for (const fp of this.pgp.publicKeys.keys()) out.set('key:' + fp, { type: 'key', data: this._keyData(fp) });
    for (const fp of this.pgp.syncedFingerprints()) {
      const d = this._passData(fp);
      if (d) out.set('passphrase:' + fp, { type: 'passphrase', data: d });
    }
    return out;
  }

  /** One item as it is on this PC right now (null = doesn't exist here). */
  localData(id) {
    const [type, key] = splitId(id);
    if (type === 'settings') return this._syncedSettings();
    if (type === 'account') return this.store.data.accounts.some(a => a.id === key) ? this._accountData(key) : null;
    if (type === 'contact') { const c = this.contacts.get(key); return c ? { ...c } : null; }
    if (type === 'key') return this._keyData(key);
    if (type === 'passphrase') return this._passData(key.toUpperCase());
    return null;
  }

  /* =================================================================
   * 5. APPLYING ITEMS FROM THE SERVER
   *    data === null means "deleted on another device".
   * ================================================================= */
  async applyItem(id, data, changes) {
    const [type, key] = splitId(id);

    /* ---- settings ---- */
    if (type === 'settings') {
      if (!data) return;
      const keep = {};
      const cur = this.store.getSettings();
      for (const k of LOCAL_SETTINGS) if (k in cur) keep[k] = cur[k];
      const next = { ...data };
      for (const k of LOCAL_SETTINGS) delete next[k];
      this.store.data.settings = { ...cur, ...next, ...keep };
      this.store._save();
      changes.settings = true;
      return;
    }

    /* ---- accounts ---- */
    if (type === 'account') {
      if (!data) {
        if (this.store.data.accounts.some(a => a.id === key)) { this.store.deleteAccount(key); changes.accounts.add(key); }
        return;
      }
      // the same mailbox set up separately on this PC: the vault's copy replaces it
      const ident = a => ((a.email || '') + '|' + (a.imapHost || '')).toLowerCase();
      for (const dup of this.store.data.accounts.filter(a => a.id !== key && ident(a) === ident(data))) {
        this.store.deleteAccount(dup.id);
        changes.accounts.add(dup.id);
      }
      this.store.saveAccount({ ...data, id: key });
      changes.accounts.add(key);
      return;
    }

    /* ---- contacts ---- */
    if (type === 'contact') {
      if (!data) { if (this.contacts.get(key)) { this.contacts.delete(key); changes.contacts = true; } return; }
      const c = { ...data, id: key };
      if (c.keyFp && !this.pgp.publicKeys.has(c.keyFp)) c.keyFp = null; // key not here (yet)
      this.contacts.applyRemote(c);
      changes.contacts = true;
      return;
    }

    /* ---- remembered-everywhere passphrases (1.5.0) ---- */
    if (type === 'passphrase') {
      const fp = key.toUpperCase();
      if (!data) { this.pgp.clearSyncedPassphrase(fp); this.pgp.unlocked.delete(fp); }
      else if (data.passphrase) this.pgp.setSyncedPassphrase(fp, String(data.passphrase));
      changes.keys = true;
      return;
    }

    /* ---- keys ---- */
    if (type === 'key') {
      const fp = key.toUpperCase();
      if (!data) {
        if (!this.pgp.publicKeys.has(fp)) return;
        if (this.pgp.privateKeys.has(fp)) {
          // never destroy a secret key because another device said so: park it in a folder
          fs.mkdirSync(this.quarantineDir, { recursive: true });
          const stamp = new Date().toISOString().replace(/[:.]/g, '-');
          fs.writeFileSync(path.join(this.quarantineDir, `${fp}-${stamp}.asc`), this.pgp.exportPrivate(fp));
          const rev = path.join(this.pgp.privDir, fp + '.rev');
          if (fs.existsSync(rev)) fs.copyFileSync(rev, path.join(this.quarantineDir, `${fp}-${stamp}.rev`));
          changes.quarantined.push(fp);
        }
        this.pgp.deleteKey(fp, { includePrivate: true });
        this.contacts.forgetKey(fp);
        changes.keys = true;
        return;
      }
      if (data.secret) {
        const cur = this.pgp.privateKeys.get(fp);
        if (!cur || cur.armor() !== data.secret) {
          const r = await this.pgp.importKeys(data.secret);
          if (r.secret.length) changes.secretKeys = true;
        }
      }
      if (data.public) await this.pgp.importKeys(data.public);
      if (data.revocation && this.pgp.privateKeys.has(fp)) {
        const rev = path.join(this.pgp.privDir, fp + '.rev');
        if (!fs.existsSync(rev)) fs.writeFileSync(rev, data.revocation);
      }
      if (data.trust) this.pgp.setTrust(fp, data.trust);
      changes.keys = true;
    }
  }

  /* =================================================================
   * 6. CONFLICTS — changed here AND on another device since last sync
   *    keys      merged (PGP keys combine safely: new user ids,
   *              signatures, extended expiry, revocations are all kept)
   *    first sync of an item on this PC: the vault's copy wins
   *    deleted on one side, edited on the other: the edit wins
   *    edited on both: the newer edit wins
   *  Returns 'remote' (server copy applied, clean), 'merge' (applied
   *  but this PC's result must be uploaded) or 'local' (keep this PC's).
   * ================================================================= */
  _decide(id, localData, remote, base) {
    const [type] = splitId(id);
    if (type === 'key' && localData && remote.data) return 'merge';
    if (!base) return remote.data ? 'remote' : 'local';
    if (!remote.data) return 'local';      // deleted elsewhere, edited here -> keep the edit
    if (!localData) return 'remote';       // deleted here, edited elsewhere -> bring it back
    const remoteTime = Number(remote.updated) || 0;
    const localTime = this._editTime(type, localData);
    return localTime > remoteTime ? 'local' : 'remote';
  }

  /* =================================================================
   * 7. THE SYNC RUN
   * ================================================================= */
  /** Start a sync (or join the one already running). */
  sync(reason = 'manual') {
    if (!this.connected() || (this.state.needs)) return Promise.resolve(this.status());
    if (this.running) { this.again = true; return this.running; }
    this.running = (async () => {
      this.onEvent('cloudsync', { running: true, reason });
      let result;
      try {
        do {
          this.again = false;
          result = await this._run();
        } while (this.again);
        this.state.lastError = null;
        this.state.lastSync = new Date().toISOString();
      } catch (e) {
        if (this.state) {
          this.state.lastError = e.message;
          if (e.code === 'key_changed') this.state.needs = 'passphrase';
          if (e.code === 'not_signed_in') this.state.needs = 'signin';
        }
        result = { error: e.message, code: e.code };
      } finally {
        this._save();
        this.running = null;
      }
      this.onEvent('cloudsync', { running: false, ...this.status(), result });
      return { ...this.status(), result };
    })();
    return this.running;
  }

  async _run() {
    const vk = this._vaultKey();
    if (!vk) throw new Error('Sync isn\'t set up on this PC');
    const s = this.state;
    s.items = s.items || {};
    const changes = { settings: false, accounts: new Set(), contacts: false, keys: false, secretKeys: false, quarantined: [] };
    const stats = { pulled: 0, applied: 0, pushed: 0, conflicts: 0, skipped: [] };

    /* ---- 7a. pull everything newer than our cursor ---- */
    const incoming = new Map();
    let since = s.seq || 0;
    for (;;) {
      const r = await this._api('pull', { since, limit: 500 });
      if (r.keyVersion !== s.keyVersion) { const e = new Error('The vault passphrase was changed on another device. Enter the new passphrase.'); e.code = 'key_changed'; throw e; }
      for (const it of r.items) { incoming.set(it.id, it); since = Math.max(since, it.seq); }
      if (!r.more) break;
    }
    stats.pulled = incoming.size;

    /* ---- 7b. apply what changed elsewhere (keys first) ---- */
    const ordered = [...incoming.values()].sort((a, b) => (TYPE_ORDER[splitId(a.id)[0]] ?? 9) - (TYPE_ORDER[splitId(b.id)[0]] ?? 9));
    for (const it of ordered) {
      const base = s.items[it.id];
      if (base && it.seq <= base.seq) continue;          // our own upload coming back
      let remote;
      try { remote = this._open(vk, it); }
      catch (e) { stats.skipped.push(it.id + ': ' + e.message); continue; }
      await this._resolve(it.id, remote, changes, stats);
    }
    s.seq = since;
    this._save();

    /* ---- 7c. push what changed here (conflicts handled, up to 3 rounds) ---- */
    for (let round = 0; round < 3; round++) {
      const local = await this.collectLocal();
      const outgoing = [];
      const ids = new Set([...local.keys(), ...Object.keys(s.items)]);
      for (const id of ids) {
        const loc = local.get(id);
        const h = loc ? hashOf(loc.data) : null;
        const base = s.items[id];
        if ((base ? base.hash : null) === h) continue;      // unchanged
        if (!loc && !base) continue;
        outgoing.push({
          id,
          base: base ? base.seq : 0,
          deleted: !loc,
          data: loc ? this._seal(vk, id, loc.type, loc.data) : undefined,
          _hash: h
        });
      }
      if (!outgoing.length) break;

      let conflicts = 0;
      for (let i = 0; i < outgoing.length; i += 100) {
        const batch = outgoing.slice(i, i + 100);
        const r = await this._api('push', { keyVersion: s.keyVersion, items: batch.map(({ _hash, ...x }) => x) });
        for (const res of r.results) {
          const sent = batch.find(b => b.id === res.id);
          if (res.ok) { s.items[res.id] = { seq: res.seq, hash: sent._hash }; stats.pushed++; continue; }
          if (res.conflict) {
            conflicts++;
            let remote;
            try { remote = this._open(vk, res.server); } catch (e) { stats.skipped.push(res.id + ': ' + e.message); continue; }
            await this._resolve(res.id, remote, changes, stats);
          } else stats.skipped.push(res.id + ': ' + (res.error || 'refused'));
        }
        this._save();
      }
      if (!conflicts) break;
    }

    // let main.js / the window react to what changed here
    const any = changes.settings || changes.accounts.size || changes.contacts || changes.keys;
    if (any) {
      const summary = { ...changes, accounts: [...changes.accounts] };
      try { await this.onApplied(summary); } catch (e) { console.warn('onApplied failed', e.message); }
      this.onEvent('cloudsync-applied', summary);
    }
    return stats;
  }

  /** Decrypt a server item: { id, seq, deleted, updated, data } -> { seq, data|null, updated } */
  _open(vk, it) {
    if (it.deleted || !it.data) return { seq: it.seq, data: null, updated: (it.updated || 0) * 1000 };
    const env = JSON.parse(unseal(vk, it.data, it.id).toString('utf8'));
    if (env.id !== it.id) throw new Error('item id mismatch');
    return { seq: it.seq, data: env.data, updated: env.updated || (it.updated || 0) * 1000 };
  }

  /** When this PC's version of an item was last edited (best estimate). */
  _editTime(type, data) {
    const own = type === 'contact' && data && Date.parse(data.updated);
    return own || this.lastLocalChange || Date.now();
  }

  _seal(vk, id, type, data) {
    const env = { v: 1, id, type, updated: this._editTime(type, data), device: this.state.deviceName, data };
    return seal(vk, Buffer.from(JSON.stringify(env), 'utf8'), id);
  }

  /** Bring one server item in, deciding conflicts; updates the saved per-item state. */
  async _resolve(id, remote, changes, stats) {
    const s = this.state;
    const base = s.items[id];
    const localData = this.localData(id);
    const localHash = hashOf(localData);
    const changedHere = localHash !== (base ? base.hash : null);

    let decision = 'remote';
    if (changedHere) {
      // identical content on both sides is not a conflict
      if (localHash === hashOf(remote.data)) decision = 'same';
      else { decision = this._decide(id, localData, remote, base); stats.conflicts++; }
    }

    if (decision === 'same') { s.items[id] = { seq: remote.seq, hash: localHash }; return; }
    if (decision === 'local') { s.items[id] = { seq: remote.seq, hash: '#upload' }; return; } // forces an upload based on the server's version

    await this.applyItem(id, remote.data, changes);
    stats.applied++;
    const after = hashOf(this.localData(id));
    // 'merge': upload the combined result once; otherwise what we have now counts as in sync
    s.items[id] = { seq: remote.seq, hash: decision === 'merge' ? '#upload' : after };
    if (decision !== 'merge' && after === null) s.items[id].hash = null;
  }

  /* =================================================================
   * 8. CONNECT / DISCONNECT / PASSPHRASE / DEVICES
   * ================================================================= */
  /** Check an address before asking for anything else. */
  async probe(serverInput) {
    const server = normalizeServer(serverInput);
    const r = await this._api('ping', null, { server, auth: false, timeout: 15000 });
    if (r.app !== 'sealpost-sync') throw new Error('No Sealpost sync server at that address');
    if (r.api > API_VERSION) throw new Error('This server is newer than this Sealpost. Update Sealpost first.');
    return { server: server.replace(/api\.php$/i, ''), vault: !!r.vault, setupOpen: !!r.setupOpen };
  }

  /**
   * Create the vault (create=true, needs setupCode) or sign in to it.
   * Then runs the first sync, which merges this PC's data with the vault.
   */
  async connect({ server: serverInput, username, passphrase, create = false, setupCode = '', deviceName }) {
    const server = normalizeServer(serverInput);
    username = String(username || '').trim().toLowerCase();
    if (!/^[a-z0-9._@+-]{3,64}$/.test(username)) throw new Error('Usernames are 3–64 characters: letters, numbers and . _ @ + -');
    if (!passphrase || passphrase.length < 10) throw new Error('Use a vault passphrase of at least 10 characters');
    deviceName = String(deviceName || os.hostname() || 'Sealpost').slice(0, 64);

    let vaultKey, r, keyVersion;
    if (create) {
      vaultKey = crypto.randomBytes(32);
      const { authKey, wrapKey } = await deriveKeys(passphrase, username, DEFAULT_KDF);
      const wrappedKey = seal(wrapKey, vaultKey, WRAP_AAD);
      r = await this._api('setup', { setupCode, username, authKey, kdf: DEFAULT_KDF, wrappedKey, deviceName, kind: 'app' }, { server, auth: false });
      keyVersion = r.keyVersion;
    } else {
      const pre = await this._api('prelogin', { username }, { server, auth: false });
      const { authKey, wrapKey } = await deriveKeys(passphrase, username, pre.kdf);
      r = await this._api('login', { username, authKey, deviceName, kind: 'app' }, { server, auth: false });
      try { vaultKey = unseal(wrapKey, r.wrappedKey, WRAP_AAD); }
      catch { throw new Error('Signed in, but the vault key could not be opened with this passphrase'); }
      keyVersion = r.keyVersion;
    }

    this.state = {
      server, username, deviceName,
      deviceId: r.deviceId,
      token: this._protect(Buffer.from(r.token, 'utf8')),
      vaultKey: this._protect(vaultKey),
      keyVersion, seq: 0, items: {},
      connectedAt: new Date().toISOString(),
      lastSync: null, lastError: null, needs: null
    };
    vaultKey.fill(0);
    this._save();
    return this.sync('connect');
  }

  /** After the passphrase changed elsewhere (or this device was signed out). */
  async reauth(passphrase) {
    if (!this.state) throw new Error('Sync isn\'t set up');
    const s = this.state;
    if (s.needs === 'signin') {
      // token no longer valid: sign in again as a fresh device, keep our sync bookkeeping
      const pre = await this._api('prelogin', { username: s.username }, { auth: false });
      const { authKey, wrapKey } = await deriveKeys(passphrase, s.username, pre.kdf);
      const r = await this._api('login', { username: s.username, authKey, deviceName: s.deviceName, kind: 'app' }, { auth: false });
      const vk = unseal(wrapKey, r.wrappedKey, WRAP_AAD);
      s.token = this._protect(Buffer.from(r.token, 'utf8'));
      s.deviceId = r.deviceId;
      s.vaultKey = this._protect(vk);
      s.keyVersion = r.keyVersion;
    } else {
      const m = await this._api('meta', {});
      const { wrapKey } = await deriveKeys(passphrase, s.username, m.kdf);
      let vk;
      try { vk = unseal(wrapKey, m.wrappedKey, WRAP_AAD); } catch { throw new Error('That isn\'t the vault passphrase'); }
      s.vaultKey = this._protect(vk);
      s.keyVersion = m.keyVersion;
    }
    s.needs = null; s.lastError = null;
    this._save();
    return this.sync('reauth');
  }

  /** New vault passphrase. The vault key stays; only its wrapping changes. */
  async changePassphrase({ current, next, signOutOthers = false }) {
    if (!this.connected()) throw new Error('Sync isn\'t set up');
    if (!next || next.length < 10) throw new Error('Use a vault passphrase of at least 10 characters');
    const s = this.state;
    const m = await this._api('meta', {});
    const oldKeys = await deriveKeys(current, s.username, m.kdf);
    try { unseal(oldKeys.wrapKey, m.wrappedKey, WRAP_AAD); } catch { throw new Error('The current passphrase is not correct'); }
    const newKeys = await deriveKeys(next, s.username, DEFAULT_KDF);
    const wrappedKey = seal(newKeys.wrapKey, this._vaultKey(), WRAP_AAD);
    const r = await this._api('changeAuth', { authKey: oldKeys.authKey, newAuthKey: newKeys.authKey, kdf: DEFAULT_KDF, wrappedKey, signOutOthers: !!signOutOthers });
    s.keyVersion = r.keyVersion;
    this._save();
    return this.status();
  }

  async devices() {
    const r = await this._api('devices', {});
    return r.devices;
  }

  async revoke(id) {
    return this._api('revoke', { id });
  }

  /** Stop syncing on this PC. Your data here stays; the vault stays. */
  async disconnect({ signOut = true } = {}) {
    if (this.state && signOut) { try { await this._api('logout', {}, { timeout: 8000 }); } catch { /* offline: token is simply forgotten */ } }
    this.state = null;
    this._save();
    return { connected: false };
  }
}

function splitId(id) {
  const i = id.indexOf(':');
  return [id.slice(0, i), id.slice(i + 1)];
}

module.exports = { SyncService, deriveKeys, seal, unseal, normalizeServer, hashOf, stable, LOCAL_SETTINGS };
