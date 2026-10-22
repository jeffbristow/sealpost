/* =====================================================================
 * Sealpost — pgp.js
 * ---------------------------------------------------------------------
 * OpenPGP engine and keyring (built on OpenPGP.js, the same library
 * used by Proton Mail and Mailvelope).
 *
 * Keyring layout on disk  (<userData>/keyring/)
 *   public/<FINGERPRINT>.asc    public keys (yours and contacts')
 *   private/<FINGERPRINT>.asc   your secret keys, ALWAYS stored
 *                               passphrase-encrypted
 *   private/<FINGERPRINT>.rev   revocation certificate made at keygen
 *   meta.json                   trust levels / notes per key
 *
 * Sections below:
 *   1. Keyring load/save
 *   2. Key description (what the UI shows)
 *   3. Key generation / import / export / delete
 *   4. Passphrase handling + unlocked-key cache
 *   5. Encrypt / decrypt / sign / verify primitives
 *   6. Key lookup online (WKD + keys.openpgp.org)
 * ===================================================================== */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const openpgp = require('openpgp');

class PgpEngine {
  /**
   * @param secure  optional { encrypt(str)->string, decrypt(string)->str }
   *                (Windows DPAPI via Electron safeStorage) — enables
   *                "Remember passphrase".
   */
  constructor(dataDir, settingsFn, secure) {
    this.dir = path.join(dataDir, 'keyring');
    this.pubDir = path.join(this.dir, 'public');
    this.privDir = path.join(this.dir, 'private');
    this.metaFile = path.join(this.dir, 'meta.json');
    fs.mkdirSync(this.pubDir, { recursive: true });
    fs.mkdirSync(this.privDir, { recursive: true });
    this.settingsFn = settingsFn || (() => ({ passphraseCacheMinutes: 15 }));
    this.secure = secure || null;
    this.rememberFile = path.join(this.dir, 'remembered.json');
    this.syncedPassFile = path.join(this.dir, 'synced-passphrases.json'); // 1.5.0
    this.publicKeys = new Map();   // fp -> openpgp PublicKey
    this.privateKeys = new Map();  // fp -> openpgp PrivateKey (locked)
    this.unlocked = new Map();     // fp -> { key, expires }
    this.meta = {};
  }

  /* =================================================================
   * 1. KEYRING LOAD / SAVE
   * ================================================================= */
  async load() {
    this.publicKeys.clear();
    this.privateKeys.clear();
    try { this.meta = JSON.parse(fs.readFileSync(this.metaFile, 'utf8')); } catch { this.meta = {}; }

    for (const f of fs.readdirSync(this.pubDir).filter(f => f.endsWith('.asc'))) {
      try {
        const key = await openpgp.readKey({ armoredKey: fs.readFileSync(path.join(this.pubDir, f), 'utf8') });
        this.publicKeys.set(key.getFingerprint().toUpperCase(), key);
      } catch (e) { console.warn('Skipping unreadable public key', f, e.message); }
    }
    for (const f of fs.readdirSync(this.privDir).filter(f => f.endsWith('.asc'))) {
      try {
        const key = await openpgp.readPrivateKey({ armoredKey: fs.readFileSync(path.join(this.privDir, f), 'utf8') });
        this.privateKeys.set(key.getFingerprint().toUpperCase(), key);
      } catch (e) { console.warn('Skipping unreadable private key', f, e.message); }
    }
  }

  _saveMeta() { fs.writeFileSync(this.metaFile, JSON.stringify(this.meta, null, 2)); }

  _writePublic(key) {
    const fp = key.getFingerprint().toUpperCase();
    fs.writeFileSync(path.join(this.pubDir, fp + '.asc'), key.armor());
    this.publicKeys.set(fp, key);
    return fp;
  }

  _writePrivate(key) {
    if (!key.isDecrypted || key.isDecrypted()) {
      // safety net — never persist an unprotected secret key
      throw new Error('Refusing to store a private key that is not passphrase protected');
    }
    const fp = key.getFingerprint().toUpperCase();
    fs.writeFileSync(path.join(this.privDir, fp + '.asc'), key.armor());
    this.privateKeys.set(fp, key);
    this._writePublic(key.toPublic());
    return fp;
  }

  /* =================================================================
   * 2. KEY DESCRIPTION (data shown in the Key Manager)
   * ================================================================= */
  async describe(key) {
    const fp = key.getFingerprint().toUpperCase();
    const algo = key.getAlgorithmInfo();
    let expires = null;
    try {
      const t = await key.getExpirationTime();
      expires = t === Infinity || t === null ? null : new Date(t).toISOString();
    } catch { /* ignore */ }
    let revoked = false;
    try { revoked = await key.isRevoked(); } catch { /* ignore */ }
    let canEncrypt = false, canSign = false;
    try { await key.getEncryptionKey(); canEncrypt = true; } catch { /* no usable enc subkey */ }
    try { await key.getSigningKey(); canSign = true; } catch { /* no usable sign key */ }

    return {
      fingerprint: fp,
      fingerprintPretty: fp.replace(/(.{4})/g, '$1 ').trim(),
      keyId: key.getKeyID().toHex().toUpperCase(),
      userIds: key.getUserIDs(),
      emails: this._emailsOf(key),
      algorithm: friendlyAlgo(algo),
      created: key.getCreationTime().toISOString(),
      expires,
      expired: expires ? new Date(expires) < new Date() : false,
      revoked,
      canEncrypt,
      canSign,
      hasPrivate: this.privateKeys.has(fp),
      unlocked: this._getUnlocked(fp) !== null,
      passphraseRemembered: this.privateKeys.has(fp) && this.hasRemembered(fp),
      passphraseSynced: this.privateKeys.has(fp) && this.hasSyncedPassphrase(fp), // 1.5.0
      trust: (this.meta[fp] && this.meta[fp].trust) || 'unknown',
      hasRevocationCert: fs.existsSync(path.join(this.privDir, fp + '.rev'))
    };
  }

  _emailsOf(key) {
    return key.getUserIDs()
      .map(u => { const m = u.match(/<([^>]+)>/); return (m ? m[1] : u).trim().toLowerCase(); })
      .filter(e => e.includes('@'));
  }

  async listKeys() {
    const out = [];
    for (const key of this.publicKeys.values()) out.push(await this.describe(key));
    // private keys first, then alphabetical by first user id
    out.sort((a, b) => (b.hasPrivate - a.hasPrivate) || (a.userIds[0] || '').localeCompare(b.userIds[0] || ''));
    return out;
  }

  /* =================================================================
   * 3. KEY GENERATION / IMPORT / EXPORT / DELETE
   * ================================================================= */
  async generate({ name, email, passphrase, algorithm = 'ecc', expireYears = 2 }) {
    if (!passphrase || passphrase.length < 8) throw new Error('Use a passphrase of at least 8 characters');
    if (!email) throw new Error('Email is required');
    const opts = {
      userIDs: [{ name: name || undefined, email }],
      passphrase,
      format: 'armored',
      keyExpirationTime: Number(expireYears) > 0 ? Math.round(Number(expireYears) * 365.25 * 86400) : 0
    };
    if (algorithm === 'rsa4096') { opts.type = 'rsa'; opts.rsaBits = 4096; }
    else { opts.type = 'ecc'; opts.curve = 'curve25519Legacy'; } // Ed25519 + Cv25519, widest compatibility

    const { privateKey, revocationCertificate } = await openpgp.generateKey(opts);
    const key = await openpgp.readPrivateKey({ armoredKey: privateKey });
    const fp = this._writePrivate(key);
    fs.writeFileSync(path.join(this.privDir, fp + '.rev'), revocationCertificate);
    this.meta[fp] = { ...(this.meta[fp] || {}), trust: 'ultimate' };
    this._saveMeta();
    return this.describe(key);
  }

  /** Import one or many keys from armored text or binary. Returns summary. */
  async importKeys(input) {
    let keys = [];
    const asText = typeof input === 'string' ? input : Buffer.from(input).toString('utf8');
    try {
      if (asText.includes('-----BEGIN PGP')) {
        // a file can contain several armored blocks
        const blocks = asText.match(/-----BEGIN PGP (PUBLIC|PRIVATE) KEY BLOCK-----[\s\S]*?-----END PGP \1 KEY BLOCK-----/g) || [asText];
        for (const b of blocks) keys.push(...(await openpgp.readKeys({ armoredKeys: b })));
      } else {
        keys = await openpgp.readKeys({ binaryKeys: new Uint8Array(Buffer.from(input)) });
      }
    } catch (e) {
      throw new Error('Could not read a PGP key from that data: ' + e.message);
    }

    const result = { imported: [], updated: [], secret: [] };
    for (const key of keys) {
      const fp = key.getFingerprint().toUpperCase();
      if (key.isPrivate()) {
        if (key.isDecrypted()) {
          throw new Error('The private key ' + fp + ' has no passphrase. Protect it with a passphrase (e.g. gpg --passwd) before importing.');
        }
        this._writePrivate(key);
        result.secret.push(fp);
        if (!this.meta[fp]) { this.meta[fp] = { trust: 'ultimate' }; }
      } else {
        const existing = this.publicKeys.get(fp);
        if (existing) {
          // merge new user ids / signatures / revocations into the stored copy
          const merged = await existing.update(key);
          this._writePublic(merged);
          result.updated.push(fp);
        } else {
          this._writePublic(key);
          result.imported.push(fp);
        }
      }
    }
    this._saveMeta();
    return result;
  }

  exportPublic(fp) {
    const key = this.publicKeys.get(fp);
    if (!key) throw new Error('Key not found');
    return key.armor();
  }

  exportPrivate(fp) {
    const key = this.privateKeys.get(fp);
    if (!key) throw new Error('No private key for ' + fp);
    return key.armor(); // still passphrase-protected
  }

  exportRevocation(fp) {
    const f = path.join(this.privDir, fp + '.rev');
    if (!fs.existsSync(f)) throw new Error('No revocation certificate stored for this key');
    return fs.readFileSync(f, 'utf8');
  }

  deleteKey(fp, { includePrivate = false } = {}) {
    if (this.privateKeys.has(fp) && !includePrivate) {
      throw new Error('This key has a secret part. Confirm private key deletion.');
    }
    for (const f of [path.join(this.pubDir, fp + '.asc'), path.join(this.privDir, fp + '.asc'), path.join(this.privDir, fp + '.rev')]) {
      if (fs.existsSync(f)) fs.unlinkSync(f);
    }
    this.publicKeys.delete(fp);
    this.privateKeys.delete(fp);
    this.unlocked.delete(fp);
    try { this.forgetPassphrase(fp); } catch { /* none saved */ }
    try { this.clearSyncedPassphrase(fp); } catch { /* none saved */ }
    delete this.meta[fp];
    this._saveMeta();
  }

  setTrust(fp, trust) {
    this.meta[fp] = { ...(this.meta[fp] || {}), trust };
    this._saveMeta();
  }

  /** Revoke one of your own keys using its stored revocation certificate. */
  async revoke(fp) {
    const key = this.privateKeys.get(fp);
    if (!key) throw new Error('You can only revoke your own keys');
    const cert = this.exportRevocation(fp);
    const { privateKey } = await openpgp.revokeKey({ key, revocationCertificate: cert, format: 'object' });
    this._writePrivate(privateKey);
    return this.describe(privateKey);
  }

  /* =================================================================
   * 4. PASSPHRASES + UNLOCKED KEY CACHE
   * -----------------------------------------------------------------
   * 4a. Unlocked keys are cached in memory for the time set in Settings.
   * 4b. "Remember passphrase" (added 1.0.2): the passphrase is encrypted
   *     with Windows DPAPI (tied to your Windows login) and saved in
   *     keyring/remembered.json. When a key is needed and not unlocked,
   *     it is unlocked automatically with the saved passphrase — no prompt.
   * ================================================================= */
  _getUnlocked(fp) {
    const c = this.unlocked.get(fp);
    if (!c) return null;
    if (c.expires && Date.now() > c.expires) { this.unlocked.delete(fp); return null; }
    return c.key;
  }

  _cacheUnlocked(fp, decrypted) {
    const mins = Number(this.settingsFn().passphraseCacheMinutes) || 0;
    this.unlocked.set(fp, { key: decrypted, expires: mins > 0 ? Date.now() + mins * 60000 : Date.now() + 5000 });
  }

  async unlock(fp, passphrase, remember = false) {
    const key = this.privateKeys.get(fp);
    if (!key) throw new Error('No private key ' + fp);
    let decrypted;
    try {
      decrypted = await openpgp.decryptKey({ privateKey: key, passphrase });
    } catch {
      throw new Error('Wrong passphrase');
    }
    this._cacheUnlocked(fp, decrypted);
    if (remember) this._saveRemembered(fp, passphrase);
    return true;
  }

  lockAll() { this.unlocked.clear(); }

  /** Your private keys that this passphrase opens, decrypted in memory only (1.3.0: opens the offline cache). */
  async decryptedKeysFor(passphrase) {
    const out = [];
    for (const key of this.privateKeys.values()) {
      try { out.push(await openpgp.decryptKey({ privateKey: key, passphrase })); } catch { /* not this one */ }
    }
    return out;
  }

  /** True if the passphrase opens any of your private keys (app-lock recovery, 1.1.0). */
  async verifyAnyPassphrase(passphrase) {
    if (!passphrase) return false;
    for (const key of this.privateKeys.values()) {
      try { await openpgp.decryptKey({ privateKey: key, passphrase }); return true; } catch { /* try next */ }
    }
    return false;
  }

  async changePassphrase(fp, oldPass, newPass) {
    if (!newPass || newPass.length < 8) throw new Error('New passphrase must be at least 8 characters');
    const key = this.privateKeys.get(fp);
    if (!key) throw new Error('No private key');
    let dec;
    try { dec = await openpgp.decryptKey({ privateKey: key, passphrase: oldPass }); }
    catch { throw new Error('Current passphrase is wrong'); }
    const enc = await openpgp.encryptKey({ privateKey: dec, passphrase: newPass });
    this._writePrivate(enc);
    this.unlocked.delete(fp);
    // keep a remembered passphrase in step with the new one
    if (this.hasRemembered(fp)) this._saveRemembered(fp, newPass);
    if (this.hasSyncedPassphrase(fp)) this.setSyncedPassphrase(fp, newPass); // 1.5.0: other devices get the new one
  }

  /* ---------- 4b. Remembered passphrases (DPAPI protected) ---------- */
  canRemember() { return !!this.secure; }

  _loadRemembered() {
    try { return JSON.parse(fs.readFileSync(this.rememberFile, 'utf8')); } catch { return {}; }
  }

  _saveRemembered(fp, passphrase) {
    if (!this.secure) throw new Error('Secure storage is not available on this computer');
    const all = this._loadRemembered();
    all[fp] = this.secure.encrypt(passphrase);
    fs.writeFileSync(this.rememberFile, JSON.stringify(all, null, 2));
  }

  hasRemembered(fp) { return !!this._loadRemembered()[fp]; }

  forgetPassphrase(fp) {
    const all = this._loadRemembered();
    delete all[fp];
    fs.writeFileSync(this.rememberFile, JSON.stringify(all, null, 2));
  }

  /** Verify a passphrase, then remember it (from the Key Manager). */
  async rememberPassphrase(fp, passphrase) {
    await this.unlock(fp, passphrase, true);
    return true;
  }

  /** Try the saved passphrase (this PC's, then the one synced through your vault). */
  async _autoUnlock(fp) {
    if (!this.privateKeys.has(fp)) return null;
    const synced = this.getSyncedPassphrase(fp);
    if (synced) {
      try {
        const decrypted = await openpgp.decryptKey({ privateKey: this.privateKeys.get(fp), passphrase: synced });
        this._cacheUnlocked(fp, decrypted);
        return decrypted;
      } catch { /* doesn't match (yet) — e.g. the changed key is still on its way; try this PC's */ }
    }
    if (!this.secure) return null;
    const blob = this._loadRemembered()[fp];
    if (!blob) return null;
    let pass;
    try { pass = this.secure.decrypt(blob); } catch { return null; } // e.g. different Windows user
    try {
      const decrypted = await openpgp.decryptKey({ privateKey: this.privateKeys.get(fp), passphrase: pass });
      this._cacheUnlocked(fp, decrypted);
      return decrypted;
    } catch {
      this.forgetPassphrase(fp); // passphrase no longer matches the key — stop using it
      return null;
    }
  }

  /* ---------- 4c. "Remember on all my devices" (1.5.0) ----------
   * The passphrase travels inside your encrypted sync vault (as item
   * passphrase:<FINGERPRINT>) so every connected Sealpost — and Sealpost
   * Web — unlocks this key without asking. On this PC it is kept
   * protected by your Windows login, like "Remember passphrase". */
  _loadSynced() {
    try { return JSON.parse(fs.readFileSync(this.syncedPassFile, 'utf8')); } catch { return {}; }
  }

  _saveSynced(all) { fs.writeFileSync(this.syncedPassFile, JSON.stringify(all, null, 2)); }

  hasSyncedPassphrase(fp) { return !!this._loadSynced()[fp]; }

  getSyncedPassphrase(fp) {
    const v = this._loadSynced()[fp];
    if (!v) return null;
    try {
      if (v.startsWith('enc:') && this.secure) return this.secure.decrypt(v.slice(4));
      if (v.startsWith('b64:')) return Buffer.from(v.slice(4), 'base64').toString('utf8'); // test mode only
    } catch { /* different Windows user */ }
    return null;
  }

  /** Store without checking (used by Sync: the key itself may still be on its way). */
  setSyncedPassphrase(fp, passphrase) {
    const all = this._loadSynced();
    all[fp] = this.secure ? 'enc:' + this.secure.encrypt(passphrase) : 'b64:' + Buffer.from(passphrase, 'utf8').toString('base64');
    this._saveSynced(all);
  }

  clearSyncedPassphrase(fp) {
    const all = this._loadSynced();
    if (!(fp in all)) return;
    delete all[fp];
    this._saveSynced(all);
  }

  /** From the Key Manager: check the passphrase opens the key, then store it for syncing. */
  async syncPassphrase(fp, passphrase) {
    await this.unlock(fp, passphrase, false);
    this.setSyncedPassphrase(fp, passphrase);
    return true;
  }

  syncedFingerprints() { return Object.keys(this._loadSynced()); }

  /** Unlocked key for fp: from cache, then saved passphrase, else ask the UI. */
  async _ensureUnlocked(fp) {
    return this._getUnlocked(fp) || (await this._autoUnlock(fp)) || this._requireUnlocked(fp);
  }

  /** Throws {code:'NEED_PASSPHRASE'} so the UI can prompt and retry. */
  _requireUnlocked(fp) {
    const k = this._getUnlocked(fp);
    if (!k) {
      const err = new Error('Passphrase required');
      err.code = 'NEED_PASSPHRASE';
      err.fingerprint = fp;
      err.userId = (this.privateKeys.get(fp) || {}).getUserIDs ? this.privateKeys.get(fp).getUserIDs()[0] : fp;
      err.canRemember = this.canRemember();
      throw err;
    }
    return k;
  }

  /* =================================================================
   * 5. ENCRYPT / DECRYPT / SIGN / VERIFY
   * ================================================================= */

  /** Your secret key for an address (first usable one). */
  async findSecretFor(email) {
    email = (email || '').toLowerCase();
    for (const [fp, key] of this.privateKeys) {
      if (!this._emailsOf(key).includes(email)) continue;
      try { if (await key.isRevoked()) continue; } catch { /* ignore */ }
      try { await key.getSigningKey(); return fp; } catch { /* expired etc */ }
    }
    return null;
  }

  /** Best public key for a recipient address, or null. */
  /* ---------- Contact-assigned ("pinned") keys — added 1.1.0 ----------
   * main.js hands us a lookup: email -> pinned fingerprint (or null).
   * A pinned key is ALWAYS used for that address. If it becomes unusable
   * (expired / revoked / deleted) we do NOT silently switch to another key;
   * the composer shows why instead. */
  setPinnedLookup(fn) { this.pinnedLookup = fn; }

  _pinnedFp(email) {
    try { return this.pinnedLookup ? this.pinnedLookup(email) : null; } catch { return null; }
  }

  /** Can this public key be used to encrypt right now? */
  async _encUsable(key) {
    try { if (await key.isRevoked()) return { ok: false, reason: 'revoked' }; } catch { /* ignore */ }
    try { await key.getEncryptionKey(); return { ok: true }; }
    catch {
      let exp = null;
      try { exp = await key.getExpirationTime(); } catch { /* ignore */ }
      if (exp && exp !== Infinity && new Date(exp) < new Date()) return { ok: false, reason: 'expired' };
      return { ok: false, reason: 'unusable' };
    }
  }

  /** Newest usable key in the keyring for an address (ignores pinning). */
  async _bestKeyByEmail(email) {
    let best = null;
    for (const key of this.publicKeys.values()) {
      if (!this._emailsOf(key).includes(email)) continue;
      if (!(await this._encUsable(key)).ok) continue;
      if (!best || key.getCreationTime() > best.getCreationTime()) best = key;
    }
    return best;
  }

  /** Key used to encrypt to an address: the pinned key, else the newest usable key. */
  async findPublicFor(email) {
    email = (email || '').toLowerCase();
    const pinned = this._pinnedFp(email);
    if (pinned) {
      const key = this.publicKeys.get(pinned);
      return key && (await this._encUsable(key)).ok ? key : null;
    }
    return this._bestKeyByEmail(email);
  }

  /** Per-recipient key status for the composer chips. */
  async recipientStatus(emails) {
    const out = {};
    for (const raw of emails) {
      const e = (raw || '').toLowerCase();
      const pinned = this._pinnedFp(e);
      const info = { ok: false, pinned: !!pinned, fingerprint: null, problem: null, otherKey: null, verified: false };
      if (pinned) {
        const key = this.publicKeys.get(pinned);
        if (!key) info.problem = 'missing';
        else {
          const u = await this._encUsable(key);
          if (u.ok) { info.ok = true; info.fingerprint = pinned; } else info.problem = u.reason;
        }
        // a different key for this address exists (possible key change)
        const best = await this._bestKeyByEmail(e);
        if (best && best.getFingerprint().toUpperCase() !== pinned) info.otherKey = best.getFingerprint().toUpperCase();
      } else {
        const k = await this._bestKeyByEmail(e);
        if (k) { info.ok = true; info.fingerprint = k.getFingerprint().toUpperCase(); }
      }
      if (info.fingerprint) {
        const t = this.meta[info.fingerprint] && this.meta[info.fingerprint].trust;
        info.verified = t === 'verified' || t === 'ultimate';
      }
      out[raw] = info;
    }
    return out;
  }

  /** Fingerprint of the keyring key containing this key ID (primary or subkey). */
  fingerprintForKeyId(keyIdHex) {
    keyIdHex = String(keyIdHex || '').toUpperCase();
    for (const [fp, key] of this.publicKeys) {
      if (key.getKeys().some(k => k.getKeyID().toHex().toUpperCase() === keyIdHex)) return fp;
    }
    return null;
  }

  /** Read a key (armored or binary) without importing it: { fingerprint, emails, armored }. */
  async peekKey(input) {
    const asText = typeof input === 'string' ? input : Buffer.from(input).toString('utf8');
    const keys = asText.includes('-----BEGIN PGP')
      ? await openpgp.readKeys({ armoredKeys: asText })
      : await openpgp.readKeys({ binaryKeys: new Uint8Array(Buffer.from(input)) });
    const k = keys[0];
    return { fingerprint: k.getFingerprint().toUpperCase(), emails: this._emailsOf(k), userIds: k.getUserIDs(), armored: k.toPublic().armor() };
  }

  /* ---------- Expiry: warnings + renewal — added 1.1.0 ---------- */

  /** Your own keys that are expired or expire within `days`. */
  async expiryWarnings(days = 30) {
    const out = [];
    const soon = Date.now() + days * 86400000;
    for (const [fp, priv] of this.privateKeys) {
      const key = this.publicKeys.get(fp) || priv;
      try { if (await key.isRevoked()) continue; } catch { /* ignore */ }
      let exp = null;
      try { exp = await key.getExpirationTime(); } catch { /* ignore */ }
      // the encryption subkey can expire before the primary key
      try { const sub = await key.getEncryptionKey(); const se = await sub.getExpirationTime?.(); if (se && se !== Infinity && (!exp || exp === Infinity || se < exp)) exp = se; }
      catch { /* no usable subkey — probably expired already */ }
      if (!exp || exp === Infinity) continue;
      const t = new Date(exp).getTime();
      if (t < soon) out.push({ fingerprint: fp, userId: key.getUserIDs()[0], expires: new Date(t).toISOString(), expired: t < Date.now(), daysLeft: Math.ceil((t - Date.now()) / 86400000) });
    }
    return out;
  }

  /**
   * Extend the expiry of one of your keys (primary + all subkeys).
   * The key material and fingerprint stay the same, so contacts just
   * need the refreshed public key — not a new one.
   * years = 0 means "never expires".
   */
  async extendExpiry(fp, passphrase, years) {
    const priv = this.privateKeys.get(fp);
    if (!priv) throw new Error('You can only extend your own keys');
    try { if (await priv.isRevoked()) throw new Error('revoked'); }
    catch (e) { if (e.message === 'revoked') throw new Error('This key is revoked and cannot be extended'); }
    let dec;
    try { dec = await openpgp.decryptKey({ privateKey: priv, passphrase }); }
    catch { throw new Error('Wrong passphrase'); }

    const userIDs = priv.getUserIDs().map(u => {
      const m = u.match(/^(.*?)\s*<([^>]+)>\s*$/);
      return m ? { name: m[1].replace(/^"|"$/g, '').trim() || undefined, email: m[2].trim() } : { name: u };
    });
    // seconds from the key's creation date until the new expiry
    const created = priv.getCreationTime().getTime();
    const target = Number(years) > 0 ? Date.now() + Number(years) * 365.25 * 86400000 : 0;
    const keyExpirationTime = target ? Math.round((target - created) / 1000) : 0;

    const { privateKey } = await openpgp.reformatKey({
      privateKey: dec, userIDs, passphrase, keyExpirationTime, date: new Date(), format: 'object'
    });
    if (privateKey.getFingerprint().toUpperCase() !== fp) throw new Error('Unexpected fingerprint change — key not saved');
    this._writePrivate(privateKey);
    this.unlocked.delete(fp);
    return this.describe(privateKey);
  }

  /**
   * Encrypt (and optionally sign) binary data. Returns armored text.
   * Missing recipient keys throw an error listing who is missing.
   */
  async encrypt({ data, recipients, signerFp, encryptToSelfFp }) {
    const encryptionKeys = [];
    const missing = [];
    for (const r of recipients) {
      const k = await this.findPublicFor(r);
      if (k) encryptionKeys.push(k); else missing.push(r);
    }
    if (missing.length) {
      const err = new Error('No public key for: ' + missing.join(', '));
      err.code = 'MISSING_KEYS';
      err.missing = missing;
      throw err;
    }
    if (encryptToSelfFp && this.publicKeys.has(encryptToSelfFp)) encryptionKeys.push(this.publicKeys.get(encryptToSelfFp));
    const opts = {
      message: await openpgp.createMessage({ binary: toU8(data) }),
      encryptionKeys,
      format: 'armored'
    };
    if (signerFp) opts.signingKeys = await this._ensureUnlocked(signerFp);
    return openpgp.encrypt(opts);
  }

  /** Detached signature (armored) over exact bytes — used for PGP/MIME. */
  async signDetached({ data, signerFp }) {
    const signingKeys = await this._ensureUnlocked(signerFp);
    return openpgp.sign({
      message: await openpgp.createMessage({ binary: toU8(data) }),
      signingKeys,
      detached: true,
      format: 'armored'
    });
  }

  /** Inline cleartext signature (-----BEGIN PGP SIGNED MESSAGE-----). */
  async signCleartext({ text, signerFp }) {
    const signingKeys = await this._ensureUnlocked(signerFp);
    return openpgp.sign({ message: await openpgp.createCleartextMessage({ text }), signingKeys });
  }

  /**
   * Decrypt armored or binary PGP data. Tries every secret key that the
   * message was encrypted to; asks for a passphrase if none is unlocked.
   */
  async decrypt(input) {
    const message = typeof input === 'string' || input.includes?.('-----BEGIN')
      ? await openpgp.readMessage({ armoredMessage: Buffer.from(input).toString('utf8') })
      : await openpgp.readMessage({ binaryMessage: toU8(input) });

    const targetIds = message.getEncryptionKeyIDs().map(k => k.toHex().toUpperCase());
    const candidates = [];
    for (const [fp, key] of this.privateKeys) {
      const ids = key.getKeys().map(k => k.getKeyID().toHex().toUpperCase());
      if (ids.some(id => targetIds.includes(id)) || targetIds.includes('0000000000000000')) candidates.push(fp);
    }
    if (!candidates.length) {
      const err = new Error('This message was not encrypted to any of your keys (key IDs: ' + targetIds.join(', ') + ')');
      err.code = 'NO_SECRET_KEY';
      throw err;
    }
    let decryptionKeys = candidates.map(fp => this._getUnlocked(fp)).filter(Boolean);
    if (!decryptionKeys.length) {
      // try remembered passphrases before asking (1.0.2)
      for (const fp of candidates) { const k = await this._autoUnlock(fp); if (k) decryptionKeys.push(k); }
    }
    if (!decryptionKeys.length) this._requireUnlocked(candidates[0]); // throws NEED_PASSPHRASE

    const res = await openpgp.decrypt({
      message,
      decryptionKeys,
      verificationKeys: [...this.publicKeys.values()],
      format: 'binary'
    });
    const signatures = await this._summarizeSignatures(res.signatures);
    return { data: Buffer.from(res.data), signatures };
  }

  /** Verify a detached signature over exact bytes. */
  async verifyDetached({ data, armoredSignature }) {
    const signature = await openpgp.readSignature({ armoredSignature });
    const res = await openpgp.verify({
      message: await openpgp.createMessage({ binary: toU8(data) }),
      signature,
      verificationKeys: [...this.publicKeys.values()]
    });
    return this._summarizeSignatures(res.signatures);
  }

  /** Verify an inline cleartext-signed block. */
  async verifyCleartext(armored) {
    const message = await openpgp.readCleartextMessage({ cleartextMessage: armored });
    const res = await openpgp.verify({ message, verificationKeys: [...this.publicKeys.values()] });
    return { text: message.getText(), signatures: await this._summarizeSignatures(res.signatures) };
  }

  /** Turn OpenPGP.js signature promises into plain status objects. */
  async _summarizeSignatures(sigs) {
    const out = [];
    for (const s of sigs || []) {
      const keyId = s.keyID.toHex().toUpperCase();
      const signer = [...this.publicKeys.values()].find(k => k.getKeys().some(sk => sk.getKeyID().toHex().toUpperCase() === keyId));
      let valid = false, error = null;
      try { await s.verified; valid = true; } catch (e) { error = e.message; }
      const fp = signer ? signer.getFingerprint().toUpperCase() : null;
      out.push({
        keyId,
        valid,
        error: signer ? error : 'Signer\'s public key is not in your keyring',
        unknownKey: !signer,
        fingerprint: fp,
        signer: signer ? signer.getUserIDs()[0] : null,
        signerEmails: signer ? this._emailsOf(signer) : [],
        trust: fp && this.meta[fp] ? this.meta[fp].trust : 'unknown'
      });
    }
    return out;
  }

  /* =================================================================
   * 6. ONLINE KEY LOOKUP (WKD first, then keys.openpgp.org)
   * ================================================================= */
  async lookupOnline(email) {
    email = email.trim().toLowerCase();
    const found = [];
    const errors = [];

    // --- Web Key Directory (published by the recipient's own domain)
    try {
      const [local, domain] = email.split('@');
      const hash = zbase32(crypto.createHash('sha1').update(local).digest());
      const urls = [
        `https://openpgpkey.${domain}/.well-known/openpgpkey/${domain}/hu/${hash}?l=${encodeURIComponent(local)}`,
        `https://${domain}/.well-known/openpgpkey/hu/${hash}?l=${encodeURIComponent(local)}`
      ];
      for (const u of urls) {
        try {
          const r = await fetch(u, { signal: AbortSignal.timeout(8000) });
          if (r.ok) {
            const keys = await openpgp.readKeys({ binaryKeys: new Uint8Array(await r.arrayBuffer()) });
            for (const k of keys) found.push({ source: 'WKD (' + domain + ')', armored: k.armor(), info: await this.describe(k) });
            break;
          }
        } catch { /* try next */ }
      }
    } catch (e) { errors.push('WKD: ' + e.message); }

    // --- keys.openpgp.org (verified keyserver)
    try {
      const r = await fetch('https://keys.openpgp.org/vks/v1/by-email/' + encodeURIComponent(email), { signal: AbortSignal.timeout(10000) });
      if (r.ok) {
        const keys = await openpgp.readKeys({ armoredKeys: await r.text() });
        for (const k of keys) {
          if (!found.some(f => f.info.fingerprint === k.getFingerprint().toUpperCase())) {
            found.push({ source: 'keys.openpgp.org', armored: k.armor(), info: await this.describe(k) });
          }
        }
      } else if (r.status !== 404) errors.push('keys.openpgp.org: HTTP ' + r.status);
    } catch (e) { errors.push('keys.openpgp.org: ' + e.message); }

    return { found, errors };
  }

  /** Upload your public key to keys.openpgp.org and request email verification. */
  async publishToKeyserver(fp) {
    const armored = this.exportPublic(fp);
    const up = await fetch('https://keys.openpgp.org/vks/v1/upload', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ keytext: armored })
    });
    if (!up.ok) throw new Error('Upload failed: HTTP ' + up.status);
    const { token, status } = await up.json();
    const pending = Object.keys(status || {}).filter(a => status[a] === 'unpublished');
    if (pending.length) {
      await fetch('https://keys.openpgp.org/vks/v1/request-verify', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, addresses: pending })
      });
    }
    return { status, verificationSentTo: pending };
  }
}

/* ---------- helpers ---------- */

// Human-readable algorithm name for the Key Manager
function friendlyAlgo(a) {
  const n = String(a.algorithm || '').toLowerCase();
  if (n.startsWith('rsa')) return 'RSA ' + (a.bits || '');
  if (n.includes('eddsa') || n.includes('ed25519')) return 'ECC Curve25519 (Ed25519)';
  if (n.includes('ed448')) return 'ECC Curve448 (Ed448)';
  if (n === 'ecdsa' || n === 'ecdh') return 'ECC ' + (a.curve || '');
  if (n === 'dsa') return 'DSA ' + (a.bits || '') + ' (legacy)';
  return a.algorithm + (a.bits ? ' ' + a.bits : '') + (a.curve ? ' ' + a.curve : '');
}
function toU8(d) {
  if (d instanceof Uint8Array) return d;
  return new Uint8Array(Buffer.from(d));
}

// z-base-32 encoding used by Web Key Directory
function zbase32(buf) {
  const alphabet = 'ybndrfg8ejkmcpqxot1uwisza345h769';
  let bits = '';
  for (const b of buf) bits += b.toString(2).padStart(8, '0');
  let out = '';
  for (let i = 0; i < bits.length; i += 5) out += alphabet[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)];
  return out;
}

module.exports = { PgpEngine };
