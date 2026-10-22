/* =====================================================================
 * Sealpost — cache.js   (added 1.3.0)
 * ---------------------------------------------------------------------
 * Encrypted local copy of your mail for offline use.
 *
 * HOW IT IS PROTECTED
 *   - Everything in <userData>/cache is encrypted with a random 256-bit
 *     "data key" (AES-256-GCM, every file authenticated).
 *   - The data key is stored only in wrapped (encrypted) form:
 *       slot 1: with a key derived from your app-lock PIN
 *               (scrypt N=2^18 — about one second and 256 MB per guess,
 *               which makes guessing the PIN very slow)
 *       slot 2: encrypted to your own PGP key(s), so "Forgot PIN? Use a
 *               key passphrase" can open the cache too.
 *     It is NOT tied to the Windows login, as requested.
 *   - The data key is only in memory while Sealpost is unlocked.
 *   - Encrypted (PGP) mail is stored exactly as received — still
 *     encrypted. A decrypted copy never touches the disk.
 *   - Folder names are hashed so the file layout doesn't reveal them.
 *
 * LAYOUT
 *   cache/meta.json                       KDF params + wrapped key slots
 *   cache/<account>/folders.bin           folder list
 *   cache/<account>/<folderHash>/index.bin   message summaries + flags
 *   cache/<account>/<folderHash>/<uid>.bin   full message (as received)
 *   cache/outbox.bin  pending.bin  drafts.bin   offline queues
 *
 * Sections:
 *   1. Key management (create, unlock, rewrap, lock, destroy)
 *   2. File encryption helpers
 *   3. Folders + message index
 *   4. Message bodies + size cap
 *   5. Offline queues (outbox, flag changes, drafts)
 *   6. Usage
 * ===================================================================== */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const openpgp = require('openpgp');

const KDF = { N: 2 ** 18, r: 8, p: 1, maxmem: 512 * 1024 * 1024 };

class CacheStore {
  constructor(dataDir) {
    this.dir = path.join(dataDir, 'cache');
    this.metaFile = path.join(this.dir, 'meta.json');
    this.key = null;          // data key (Buffer) while unlocked
    this.nameKey = null;      // derived key for hashing folder names
  }

  /* =================================================================
   * 1. KEY MANAGEMENT
   * ================================================================= */
  exists() { return fs.existsSync(this.metaFile); }
  isOpen() { return !!this.key; }
  _meta() { return JSON.parse(fs.readFileSync(this.metaFile, 'utf8')); }
  _saveMeta(m) { fs.mkdirSync(this.dir, { recursive: true }); fs.writeFileSync(this.metaFile, JSON.stringify(m, null, 2)); }

  _pinKey(pin, saltHex) {
    return crypto.scryptSync(String(pin), Buffer.from(saltHex, 'hex'), 32, KDF);
  }

  _wrap(kek, dataKey) {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', kek, iv);
    const ct = Buffer.concat([c.update(dataKey), c.final()]);
    return { iv: iv.toString('hex'), tag: c.getAuthTag().toString('hex'), ct: ct.toString('hex') };
  }

  _unwrap(kek, w) {
    const d = crypto.createDecipheriv('aes-256-gcm', kek, Buffer.from(w.iv, 'hex'));
    d.setAuthTag(Buffer.from(w.tag, 'hex'));
    return Buffer.concat([d.update(Buffer.from(w.ct, 'hex')), d.final()]);
  }

  async _pgpSlot(pgp, dataKey) {
    const keys = [];
    for (const [fp] of pgp.privateKeys) {
      const pub = pgp.publicKeys.get(fp);
      try { if (pub && !(await pub.isRevoked())) { await pub.getEncryptionKey(); keys.push(pub); } } catch { /* expired etc. */ }
    }
    if (!keys.length) return null;
    return openpgp.encrypt({ message: await openpgp.createMessage({ binary: new Uint8Array(dataKey) }), encryptionKeys: keys, format: 'armored' });
  }

  _setKey(k) {
    this.key = k;
    this.nameKey = crypto.createHmac('sha256', k).update('folder-names').digest();
  }

  /** Create a new, empty cache protected by the PIN (and your PGP keys). */
  async create(pin, pgp) {
    this.destroy();
    const dataKey = crypto.randomBytes(32);
    const salt = crypto.randomBytes(16).toString('hex');
    this._saveMeta({
      version: 1, created: new Date().toISOString(),
      kdf: { alg: 'scrypt', ...KDF, maxmem: undefined, salt },
      pinSlot: this._wrap(this._pinKey(pin, salt), dataKey),
      pgpSlot: await this._pgpSlot(pgp, dataKey)
    });
    this._setKey(dataKey);
  }

  unlockWithPin(pin) {
    if (!this.exists()) return false;
    const m = this._meta();
    try { this._setKey(this._unwrap(this._pinKey(pin, m.kdf.salt), m.pinSlot)); return true; }
    catch { return false; }
  }

  /** Forgot-PIN path: one of your private keys (already decrypted) opens the cache. */
  async unlockWithPgp(decryptedKeys) {
    if (!this.exists()) return false;
    const m = this._meta();
    if (!m.pgpSlot) return false;
    try {
      const res = await openpgp.decrypt({ message: await openpgp.readMessage({ armoredMessage: m.pgpSlot }), decryptionKeys: decryptedKeys, format: 'binary' });
      this._setKey(Buffer.from(res.data));
      return true;
    } catch { return false; }
  }

  /** New PIN: only the PIN slot changes, the cache itself stays as it is. */
  rewrapPin(newPin) {
    if (!this.key || !this.exists()) return;
    const m = this._meta();
    m.kdf.salt = crypto.randomBytes(16).toString('hex');
    m.pinSlot = this._wrap(this._pinKey(newPin, m.kdf.salt), this.key);
    this._saveMeta(m);
  }

  /** Your own keys changed (new key, deleted key): refresh the PGP slot. */
  async rewrapPgp(pgp) {
    if (!this.key || !this.exists()) return;
    const m = this._meta();
    m.pgpSlot = await this._pgpSlot(pgp, this.key);
    this._saveMeta(m);
  }

  lock() { if (this.key) this.key.fill(0); this.key = null; this.nameKey = null; }

  destroy() {
    this.lock();
    fs.rmSync(this.dir, { recursive: true, force: true });
  }

  /* =================================================================
   * 2. FILE ENCRYPTION: [12-byte IV][16-byte tag][ciphertext]
   * ================================================================= */
  _need() { if (!this.key) { const e = new Error('Offline cache is locked'); e.code = 'CACHE_LOCKED'; throw e; } }

  _write(file, buf) {
    this._need();
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', this.key, iv);
    const ct = Buffer.concat([c.update(buf), c.final()]);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = file + '.tmp';
    fs.writeFileSync(tmp, Buffer.concat([iv, c.getAuthTag(), ct]));
    fs.renameSync(tmp, file);
  }

  _read(file) {
    this._need();
    if (!fs.existsSync(file)) return null;
    const b = fs.readFileSync(file);
    try {
      const d = crypto.createDecipheriv('aes-256-gcm', this.key, b.subarray(0, 12));
      d.setAuthTag(b.subarray(12, 28));
      return Buffer.concat([d.update(b.subarray(28)), d.final()]);
    } catch { return null; } // damaged/foreign file — treat as missing
  }

  _writeJson(file, obj) { this._write(file, Buffer.from(JSON.stringify(obj))); }
  _readJson(file, fallback) { const b = this._read(file); if (!b) return fallback; try { return JSON.parse(b.toString('utf8')); } catch { return fallback; } }

  _accDir(accId) { return path.join(this.dir, String(accId).replace(/[^a-z0-9-]/gi, '')); }
  _folderDir(accId, folder) {
    this._need();
    const h = crypto.createHmac('sha256', this.nameKey).update(folder).digest('hex').slice(0, 24);
    return path.join(this._accDir(accId), h);
  }

  /* =================================================================
   * 3. FOLDERS + MESSAGE INDEX
   * index = { path, uidValidity, messages: { uid: summary }, bodies: { uid: { size, at } } }
   * ================================================================= */
  saveFolders(accId, folders) { this._writeJson(path.join(this._accDir(accId), 'folders.bin'), folders); }
  getFolders(accId) { return this._readJson(path.join(this._accDir(accId), 'folders.bin'), null); }

  getIndex(accId, folder) {
    return this._readJson(path.join(this._folderDir(accId, folder), 'index.bin'), null) ||
      { path: folder, uidValidity: null, messages: {}, bodies: {} };
  }
  saveIndex(accId, folder, idx) { this._writeJson(path.join(this._folderDir(accId, folder), 'index.bin'), idx); }

  /** 1.10.0: a folder was renamed or deleted — forget what was saved for it. */
  dropFolder(accId, folder) {
    try { fs.rmSync(this._folderDir(accId, folder), { recursive: true, force: true }); } catch { /* nothing saved */ }
  }

  /** Server says the folder was rebuilt: everything cached for it is invalid. */
  resetFolder(accId, folder, uidValidity) {
    fs.rmSync(this._folderDir(accId, folder), { recursive: true, force: true });
    const idx = { path: folder, uidValidity: String(uidValidity), messages: {}, bodies: {} };
    this.saveIndex(accId, folder, idx);
    return idx;
  }

  /** Merge freshly fetched summaries into the index. */
  upsertSummaries(accId, folder, summaries, uidValidity) {
    let idx = this.getIndex(accId, folder);
    if (uidValidity != null && idx.uidValidity && idx.uidValidity !== String(uidValidity)) idx = this.resetFolder(accId, folder, uidValidity);
    if (uidValidity != null) idx.uidValidity = String(uidValidity);
    for (const s of summaries) idx.messages[s.uid] = { ...(idx.messages[s.uid] || {}), ...s };
    this.saveIndex(accId, folder, idx);
    return idx;
  }

  removeUids(accId, folder, uids) {
    const idx = this.getIndex(accId, folder);
    for (const u of uids) {
      delete idx.messages[u];
      if (idx.bodies[u]) { delete idx.bodies[u]; fs.rmSync(path.join(this._folderDir(accId, folder), u + '.bin'), { force: true }); }
    }
    this.saveIndex(accId, folder, idx);
  }

  setFlag(accId, folder, uids, flag, on) {
    const idx = this.getIndex(accId, folder);
    const key = { '\\Seen': 'seen', '\\Flagged': 'flagged', '\\Answered': 'answered' }[flag];
    if (!key) return;
    for (const u of [].concat(uids)) if (idx.messages[u]) idx.messages[u][key] = !!on;
    this.saveIndex(accId, folder, idx);
  }

  /** Offline message list: newest first, paged, optional search (headers + saved bodies). */
  listMessages(accId, folder, { page = 0, pageSize = 50, search = '' } = {}) {
    const idx = this.getIndex(accId, folder);
    let msgs = Object.values(idx.messages).map(m => ({ ...m, cached: !!idx.bodies[m.uid] }));
    if (search) {
      const q = search.toLowerCase();
      msgs = msgs.filter(m => {
        const hay = [m.subject, ...(m.from || []).map(a => a.name + ' ' + a.address), ...(m.to || []).map(a => a.name + ' ' + a.address)].join(' ').toLowerCase();
        if (hay.includes(q)) return true;
        if (!idx.bodies[m.uid] || m.encrypted) return false; // encrypted mail can't be searched without decrypting
        const raw = this.getBody(accId, folder, m.uid);
        return raw ? raw.toString('utf8').toLowerCase().includes(q) : false;
      });
    }
    msgs.sort((a, b) => new Date(b.date) - new Date(a.date) || b.uid - a.uid);
    return { total: msgs.length, messages: msgs.slice(page * pageSize, (page + 1) * pageSize), hasMore: msgs.length > (page + 1) * pageSize, offline: true };
  }

  /* =================================================================
   * 4. MESSAGE BODIES + SIZE CAP
   * ================================================================= */
  hasBody(accId, folder, uid) { return !!this.getIndex(accId, folder).bodies[uid]; }

  putBody(accId, folder, uid, raw, summary) {
    const dir = this._folderDir(accId, folder);
    this._write(path.join(dir, uid + '.bin'), raw);
    const idx = this.getIndex(accId, folder);
    if (summary) idx.messages[uid] = { ...(idx.messages[uid] || {}), ...summary };
    idx.bodies[uid] = { size: raw.length, at: Date.now() };
    this.saveIndex(accId, folder, idx);
  }

  getBody(accId, folder, uid) {
    const b = this._read(path.join(this._folderDir(accId, folder), uid + '.bin'));
    if (b) { // remember when it was last used (eviction prefers old, unused)
      const idx = this.getIndex(accId, folder);
      if (idx.bodies[uid]) { idx.bodies[uid].at = Date.now(); this.saveIndex(accId, folder, idx); }
    }
    return b;
  }

  /** Keep total size under capBytes by removing the oldest saved messages first. */
  enforceCap(capBytes, accounts) {
    const all = [];
    let total = this.usage().bytes;
    if (total <= capBytes) return 0;
    for (const accId of accounts) {
      for (const f of this.getFolders(accId) || []) {
        const idx = this.getIndex(accId, f.path);
        for (const [uid, b] of Object.entries(idx.bodies)) {
          const m = idx.messages[uid] || {};
          all.push({ accId, folder: f.path, uid, size: b.size, when: Math.max(new Date(m.date || 0).getTime(), b.at || 0) });
        }
      }
    }
    all.sort((a, b) => a.when - b.when);
    let removed = 0;
    for (const e of all) {
      if (total <= capBytes) break;
      const idx = this.getIndex(e.accId, e.folder);
      delete idx.bodies[e.uid];
      this.saveIndex(e.accId, e.folder, idx);
      fs.rmSync(path.join(this._folderDir(e.accId, e.folder), e.uid + '.bin'), { force: true });
      total -= e.size; removed++;
    }
    return removed;
  }

  /* =================================================================
   * 5. OFFLINE QUEUES
   * ================================================================= */
  _queueFile(name) { return path.join(this.dir, name + '.bin'); }
  getQueue(name) { return this._readJson(this._queueFile(name), []); }
  saveQueue(name, list) { this._writeJson(this._queueFile(name), list); }
  pushQueue(name, item) { const q = this.getQueue(name); q.push(item); this.saveQueue(name, q); return item; }

  // outbox items carry the finished raw message (already encrypted/signed when you chose that)
  addOutbox(item) { return this.pushQueue('outbox', { ...item, id: crypto.randomUUID(), queued: new Date().toISOString(), raw: item.raw.toString('base64') }); }
  outbox() { return this.getQueue('outbox'); }

  /* =================================================================
   * 6. USAGE
   * ================================================================= */
  usage() {
    let bytes = 0, files = 0;
    const walk = d => {
      if (!fs.existsSync(d)) return;
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        const p = path.join(d, e.name);
        if (e.isDirectory()) walk(p); else { bytes += fs.statSync(p).size; files++; }
      }
    };
    walk(this.dir);
    return { bytes, files };
  }
}

module.exports = { CacheStore };
