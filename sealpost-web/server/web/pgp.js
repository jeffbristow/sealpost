/* =====================================================================
 * Sealpost Web — pgp.js
 * ---------------------------------------------------------------------
 * Your PGP keyring inside the browser tab, built from the keys in your
 * vault. Secret keys stay protected by their own passphrases; a key you
 * unlock stays unlocked only in this tab's memory, for as long as your
 * "Keep private keys unlocked" setting says (and never after sign-out).
 * Keys you chose to "Remember on all my devices" unlock automatically.
 *
 * Sections:
 *   1. Keyring (load from vault items)
 *   2. Unlocking secret keys (typed, or remembered on all devices)
 *   3. Decrypting
 *   4. Verifying signatures
 *   5. Choosing keys for sending (yours, recipients', contact-assigned)
 *   6. Encrypting + signing
 *   7. Key management: describe, read/import, generate
 *   7b. Key upkeep: extend expiry, change passphrase, revoke (1.4.0)
 *   7c. Cleartext signing for PGP Tools (1.4.0)
 *   8. Helpers
 * ===================================================================== */

import * as openpgp from './vendor/openpgp.js';

export { openpgp };

export class Keyring {
  constructor() {
    this.publicKeys = new Map();   // FP -> PublicKey
    this.privateKeys = new Map();  // FP -> PrivateKey (locked)
    this.trust = {};               // FP -> 'ultimate' | 'verified' | 'untrusted' | 'unknown'
    this.unlocked = new Map();     // FP -> { key, expires }
    this.remembered = new Map();   // FP -> passphrase ("Remember on all my devices")
    this.pinned = () => null;      // email -> fingerprint assigned in Contacts
    this.cacheMinutes = 15;
  }

  /* =================================================================
   * 1. KEYRING — keys: [{ fingerprint, public, secret, trust }]
   * ================================================================= */
  async load(keys, settings = {}, remembered = new Map()) {
    this.publicKeys.clear();
    this.privateKeys.clear();
    this.trust = {};
    this.remembered = new Map(remembered);
    this.cacheMinutes = Number.isFinite(Number(settings.passphraseCacheMinutes)) ? Number(settings.passphraseCacheMinutes) : 15;
    for (const k of keys) {
      const fp = k.fingerprint.toUpperCase();
      try {
        if (k.public) this.publicKeys.set(fp, await openpgp.readKey({ armoredKey: k.public }));
        if (k.secret) {
          const sk = await openpgp.readPrivateKey({ armoredKey: k.secret });
          this.privateKeys.set(fp, sk);
          if (!this.publicKeys.has(fp)) this.publicKeys.set(fp, sk.toPublic());
        }
        if (k.trust) this.trust[fp] = k.trust;
      } catch (e) { console.warn('Skipping unreadable key', fp, e.message); }
    }
    // keys removed from the vault are forgotten here too
    for (const fp of [...this.unlocked.keys()]) if (!this.privateKeys.has(fp)) this.unlocked.delete(fp);
  }

  setPinnedLookup(fn) { this.pinned = fn; }

  /* 1.11.0: addy.io — app.js hands us email -> the address to use for keys
   * (the real recipient inside an addy.io address when "I use addy.io" is on;
   * see addy.js). Contact-assigned keys are looked up for the address as typed
   * first, then for the real one; keyring keys by the real address. */
  setAddressMap(fn) { this.addressMap = fn; }

  keyAddress(email) {
    const e = (email || '').trim().toLowerCase();
    try { return (this.addressMap && this.addressMap(e)) || e; } catch { return e; }
  }

  pinnedFor(e, k) { return this.pinned(e) || (k !== e ? this.pinned(k) : null); }

  async bestKeyFor(e, k) { return (await this.bestKeyByEmail(k)) || (k !== e ? this.bestKeyByEmail(e) : null); }

  userIdOf(fp) {
    const k = this.publicKeys.get(fp) || this.privateKeys.get(fp);
    return k ? k.getUserIDs()[0] || fp : fp;
  }

  /* =================================================================
   * 2. UNLOCKING
   * ================================================================= */
  getUnlocked(fp) {
    const u = this.unlocked.get(fp);
    if (!u) return null;
    if (u.expires && Date.now() > u.expires) { this.unlocked.delete(fp); return null; }
    return u.key;
  }

  _cache(fp, decrypted) {
    const mins = this.cacheMinutes;
    this.unlocked.set(fp, { key: decrypted, expires: Date.now() + (mins > 0 ? mins * 60000 : 15000) });
  }

  async unlock(fp, passphrase) {
    const key = this.privateKeys.get(fp);
    if (!key) throw new Error('No secret key ' + fp);
    let decrypted;
    try { decrypted = await openpgp.decryptKey({ privateKey: key, passphrase }); }
    catch { throw new Error('Wrong passphrase'); }
    this._cache(fp, decrypted);
    return decrypted;
  }

  /** Check a passphrase without keeping the key unlocked. */
  async checkPassphrase(fp, passphrase) {
    try { await openpgp.decryptKey({ privateKey: this.privateKeys.get(fp), passphrase }); return true; } catch { return false; }
  }

  /** Unlocked key, using a passphrase remembered on all devices if there is one. */
  async tryUnlocked(fp) {
    const k = this.getUnlocked(fp);
    if (k) return k;
    const p = this.remembered.get(fp);
    if (p) { try { return await this.unlock(fp, p); } catch { /* changed passphrase not synced yet */ } }
    return null;
  }

  /** Unlocked key or { code: 'NEED_PASSPHRASE' } so the page can ask and retry. */
  async requireUnlocked(fp) {
    const k = await this.tryUnlocked(fp);
    if (k) return k;
    throw Object.assign(new Error('Passphrase needed'), { code: 'NEED_PASSPHRASE', fingerprint: fp, userId: this.userIdOf(fp) });
  }

  lockAll() { this.unlocked.clear(); }

  /* =================================================================
   * 3. DECRYPTING — armored text or binary bytes
   * ================================================================= */
  async decrypt(input) {
    const message = typeof input === 'string'
      ? await openpgp.readMessage({ armoredMessage: input })
      : await this._readAny(input);
    const targetIds = message.getEncryptionKeyIDs().map(k => k.toHex().toUpperCase());
    const candidates = [];
    for (const [fp, key] of this.privateKeys) {
      const ids = key.getKeys().map(k => k.getKeyID().toHex().toUpperCase());
      if (ids.some(id => targetIds.includes(id)) || targetIds.includes('0000000000000000')) candidates.push(fp);
    }
    if (!candidates.length) {
      throw Object.assign(new Error('This message was not encrypted to any of your keys (key IDs: ' + targetIds.join(', ') + ')'), { code: 'NO_SECRET_KEY' });
    }
    const decryptionKeys = [];
    for (const fp of candidates) { const k = await this.tryUnlocked(fp); if (k) decryptionKeys.push(k); }
    if (!decryptionKeys.length) await this.requireUnlocked(candidates[0]); // throws NEED_PASSPHRASE
    const res = await openpgp.decrypt({ message, decryptionKeys, verificationKeys: [...this.publicKeys.values()], format: 'binary' });
    return { data: res.data, signatures: await this.summarize(res.signatures) };
  }

  async _readAny(bytes) {
    const head = new TextDecoder().decode(bytes.subarray(0, 100));
    if (head.includes('-----BEGIN PGP')) return openpgp.readMessage({ armoredMessage: new TextDecoder().decode(bytes) });
    return openpgp.readMessage({ binaryMessage: bytes });
  }

  /* =================================================================
   * 4. VERIFYING
   * ================================================================= */
  async verifyDetached(dataBytes, armoredSignature) {
    const signature = await openpgp.readSignature({ armoredSignature });
    const res = await openpgp.verify({ message: await openpgp.createMessage({ binary: dataBytes }), signature, verificationKeys: [...this.publicKeys.values()] });
    return this.summarize(res.signatures);
  }

  async verifyCleartext(armored) {
    const message = await openpgp.readCleartextMessage({ cleartextMessage: armored });
    const res = await openpgp.verify({ message, verificationKeys: [...this.publicKeys.values()] });
    return { text: message.getText(), signatures: await this.summarize(res.signatures) };
  }

  async summarize(sigs) {
    const out = [];
    for (const s of sigs || []) {
      const keyId = s.keyID.toHex().toUpperCase();
      const signer = [...this.publicKeys.values()].find(k => k.getKeys().some(sk => sk.getKeyID().toHex().toUpperCase() === keyId));
      let valid = false, error = null;
      try { await s.verified; valid = true; } catch (e) { error = e.message; }
      const fp = signer ? signer.getFingerprint().toUpperCase() : null;
      out.push({
        keyId, valid,
        error: signer ? error : 'Signer\'s public key is not in your keyring',
        unknownKey: !signer,
        fingerprint: fp,
        signer: signer ? signer.getUserIDs()[0] : null,
        signerEmails: signer ? emailsOf(signer) : [],
        trust: (fp && this.trust[fp]) || 'unknown'
      });
    }
    return out;
  }

  /* =================================================================
   * 5. CHOOSING KEYS FOR SENDING
   *    Same rules as Sealpost on your PC: a key assigned to a contact
   *    is always used for that contact (never silently swapped).
   * ================================================================= */
  async findSecretFor(email) {
    email = (email || '').toLowerCase();
    for (const [fp, key] of this.privateKeys) {
      if (!emailsOf(key).includes(email)) continue;
      try { if (await key.isRevoked()) continue; } catch { /* ignore */ }
      try { await key.getSigningKey(); return fp; } catch { /* expired etc */ }
    }
    return null;
  }

  async encUsable(key) {
    try { if (await key.isRevoked()) return { ok: false, reason: 'revoked' }; } catch { /* ignore */ }
    try { await key.getEncryptionKey(); return { ok: true }; }
    catch {
      let exp = null;
      try { exp = await key.getExpirationTime(); } catch { /* ignore */ }
      if (exp && exp !== Infinity && new Date(exp) < new Date()) return { ok: false, reason: 'expired' };
      return { ok: false, reason: 'unusable' };
    }
  }

  async bestKeyByEmail(email) {
    let best = null;
    for (const key of this.publicKeys.values()) {
      if (!emailsOf(key).includes(email)) continue;
      if (!(await this.encUsable(key)).ok) continue;
      if (!best || key.getCreationTime() > best.getCreationTime()) best = key;
    }
    return best;
  }

  async findPublicFor(email) {
    email = (email || '').toLowerCase();
    const k = this.keyAddress(email);                  // 1.11.0: addy.io -> real address
    const pinned = this.pinnedFor(email, k);
    if (pinned) {
      const key = this.publicKeys.get(pinned);
      return key && (await this.encUsable(key)).ok ? key : null;
    }
    return this.bestKeyFor(email, k);
  }

  /** Per-recipient status for the composer chips. */
  async recipientStatus(emails) {
    const out = {};
    for (const raw of emails) {
      const e = (raw || '').toLowerCase();
      const ka = this.keyAddress(e);                   // 1.11.0: addy.io -> real address
      const pinned = this.pinnedFor(e, ka);
      const info = { ok: false, pinned: !!pinned, fingerprint: null, problem: null, otherKey: null, verified: false, keyAddress: ka !== e ? ka : null };
      if (pinned) {
        const key = this.publicKeys.get(pinned);
        if (!key) info.problem = 'missing';
        else { const u = await this.encUsable(key); if (u.ok) { info.ok = true; info.fingerprint = pinned; } else info.problem = u.reason; }
        const best = await this.bestKeyFor(e, ka);
        if (best && best.getFingerprint().toUpperCase() !== pinned) info.otherKey = best.getFingerprint().toUpperCase();
      } else {
        const k = await this.bestKeyFor(e, ka);
        if (k) { info.ok = true; info.fingerprint = k.getFingerprint().toUpperCase(); }
      }
      if (info.fingerprint) { const t = this.trust[info.fingerprint]; info.verified = t === 'verified' || t === 'ultimate'; }
      out[raw] = info;
    }
    return out;
  }

  /* =================================================================
   * 6. ENCRYPTING + SIGNING
   * ================================================================= */
  async encrypt({ data, recipients, signerFp, encryptToSelfFp }) {
    const encryptionKeys = [], missing = [];
    for (const r of recipients) { const k = await this.findPublicFor(r); if (k) encryptionKeys.push(k); else missing.push(r); }
    if (missing.length) throw Object.assign(new Error('No public key for: ' + missing.join(', ')), { code: 'MISSING_KEYS', missing });
    if (encryptToSelfFp && this.publicKeys.has(encryptToSelfFp)) encryptionKeys.push(this.publicKeys.get(encryptToSelfFp));
    const opts = { message: await openpgp.createMessage({ binary: data }), encryptionKeys, format: 'armored' };
    if (signerFp) opts.signingKeys = await this.requireUnlocked(signerFp);
    return openpgp.encrypt(opts);
  }

  async signDetached({ data, signerFp }) {
    const signingKeys = await this.requireUnlocked(signerFp);
    return openpgp.sign({ message: await openpgp.createMessage({ binary: data }), signingKeys, detached: true, format: 'armored' });
  }

  /** "pgp-sha512" etc. — must name the hash the signature really used. */
  async micalgOf(armoredSig) {
    try {
      const sig = await openpgp.readSignature({ armoredSignature: armoredSig });
      return 'pgp-' + openpgp.enums.read(openpgp.enums.hash, sig.packets[0].hashAlgorithm).toLowerCase();
    } catch { return 'pgp-sha256'; }
  }

  /* =================================================================
   * 7. KEY MANAGEMENT
   * ================================================================= */
  async describe(fp) {
    const key = this.publicKeys.get(fp) || this.privateKeys.get(fp);
    let expires = null, revoked = false, canEncrypt = false, canSign = false;
    try { const t = await key.getExpirationTime(); expires = t === Infinity || t === null ? null : new Date(t).toISOString(); } catch { /* ignore */ }
    try { revoked = await key.isRevoked(); } catch { /* ignore */ }
    try { await key.getEncryptionKey(); canEncrypt = true; } catch { /* none */ }
    try { await key.getSigningKey(); canSign = true; } catch { /* none */ }
    const algo = key.getAlgorithmInfo();
    return {
      fingerprint: fp,
      fingerprintPretty: fp.replace(/(.{4})/g, '$1 ').trim(),
      keyId: key.getKeyID().toHex().toUpperCase(),
      userIds: key.getUserIDs(),
      emails: emailsOf(key),
      algorithm: algo.algorithm.startsWith('rsa') ? `RSA ${algo.bits}` : (algo.curve ? `ECC (${algo.curve.replace('Legacy', '')})` : algo.algorithm),
      created: key.getCreationTime().toISOString(),
      expires, expired: expires ? new Date(expires) < new Date() : false,
      revoked, canEncrypt, canSign,
      hasPrivate: this.privateKeys.has(fp),
      unlocked: !!this.getUnlocked(fp),
      remembered: this.remembered.has(fp),
      trust: this.privateKeys.has(fp) ? 'ultimate' : (this.trust[fp] || 'unknown')
    };
  }

  /** Read keys from pasted text or a file. Returns openpgp key objects. */
  async read(input) {
    const text = typeof input === 'string' ? input : new TextDecoder().decode(input);
    try {
      if (text.includes('-----BEGIN PGP')) {
        const blocks = text.match(/-----BEGIN PGP (PUBLIC|PRIVATE) KEY BLOCK-----[\s\S]*?-----END PGP \1 KEY BLOCK-----/g) || [text];
        const out = [];
        for (const b of blocks) out.push(...(await openpgp.readKeys({ armoredKeys: b })));
        return out;
      }
      return await openpgp.readKeys({ binaryKeys: typeof input === 'string' ? new TextEncoder().encode(input) : input });
    } catch (e) { throw new Error('Could not read a PGP key from that: ' + e.message); }
  }

  /**
   * Vault data for importing a key: { fingerprint, public, secret, revocation, trust }.
   * Public keys merge with a copy already in the keyring.
   */
  async importData(key, existing) {
    const fp = key.getFingerprint().toUpperCase();
    if (key.isPrivate()) {
      if (key.isDecrypted()) throw new Error('The private key ' + fp + ' has no passphrase. Protect it with a passphrase first (e.g. gpg --passwd).');
      return { fingerprint: fp, public: key.toPublic().armor(), secret: key.armor(), revocation: existing ? existing.revocation || null : null, trust: 'ultimate' };
    }
    let pub = key;
    const have = this.publicKeys.get(fp);
    if (have) { try { pub = await have.update(key); } catch { pub = key; } }
    return { fingerprint: fp, public: pub.armor(), secret: existing ? existing.secret || null : null, revocation: existing ? existing.revocation || null : null, trust: existing ? existing.trust || null : null };
  }

  /** New key pair (same defaults as Sealpost on your PC). */
  async generate({ name, email, passphrase, algorithm = 'ecc', expireYears = 2 }) {
    if (!passphrase || passphrase.length < 8) throw new Error('Use a passphrase of at least 8 characters');
    if (!email || !email.includes('@')) throw new Error('Enter an email address');
    const opts = { userIDs: [{ name: name || undefined, email }], passphrase, format: 'armored', keyExpirationTime: Number(expireYears) > 0 ? Math.round(Number(expireYears) * 365.25 * 86400) : 0 };
    if (algorithm === 'rsa4096') { opts.type = 'rsa'; opts.rsaBits = 4096; } else { opts.type = 'ecc'; opts.curve = 'curve25519Legacy'; }
    const { privateKey, publicKey, revocationCertificate } = await openpgp.generateKey(opts);
    const k = await openpgp.readPrivateKey({ armoredKey: privateKey });
    return { fingerprint: k.getFingerprint().toUpperCase(), public: publicKey, secret: privateKey, revocation: revocationCertificate, trust: 'ultimate' };
  }

  /* =================================================================
   * 7b. KEY UPKEEP — each returns new vault data for the key
   * ================================================================= */
  async _decryptFor(fp, passphrase) {
    const priv = this.privateKeys.get(fp);
    if (!priv) throw new Error('You can only change your own keys');
    try { return await openpgp.decryptKey({ privateKey: priv, passphrase }); }
    catch { throw new Error('Wrong passphrase'); }
  }

  /** New expiry (years from today; 0 = never). Same key, same fingerprint. */
  async extendExpiry(fp, passphrase, years, existing = {}) {
    const priv = this.privateKeys.get(fp);
    if (priv && await priv.isRevoked().catch(() => false)) throw new Error('This key is revoked and cannot be extended');
    const dec = await this._decryptFor(fp, passphrase);
    const userIDs = priv.getUserIDs().map(u => {
      const m = u.match(/^(.*?)\s*<([^>]+)>\s*$/);
      return m ? { name: m[1].replace(/^"|"$/g, '').trim() || undefined, email: m[2].trim() } : { name: u };
    });
    const created = priv.getCreationTime().getTime();
    const target = Number(years) > 0 ? Date.now() + Number(years) * 365.25 * 86400000 : 0;
    const { privateKey } = await openpgp.reformatKey({
      privateKey: dec, userIDs, passphrase, format: 'object', date: new Date(),
      keyExpirationTime: target ? Math.round((target - created) / 1000) : 0
    });
    if (privateKey.getFingerprint().toUpperCase() !== fp) throw new Error('Unexpected fingerprint change — key not saved');
    this.unlocked.delete(fp);
    return { ...existing, fingerprint: fp, secret: privateKey.armor(), public: privateKey.toPublic().armor(), trust: 'ultimate' };
  }

  async changePassphrase(fp, oldPass, newPass, existing = {}) {
    if (!newPass || newPass.length < 8) throw new Error('New passphrase must be at least 8 characters');
    const dec = await this._decryptFor(fp, oldPass);
    const enc = await openpgp.encryptKey({ privateKey: dec, passphrase: newPass });
    this.unlocked.delete(fp);
    return { ...existing, fingerprint: fp, secret: enc.armor() };
  }

  /** Revoke with the revocation certificate stored with the key. */
  async revoke(fp, revocationCertificate, existing = {}) {
    const priv = this.privateKeys.get(fp);
    if (!priv) throw new Error('You can only revoke your own keys');
    if (!revocationCertificate) throw new Error('No revocation certificate is stored for this key');
    const { privateKey } = await openpgp.revokeKey({ key: priv, revocationCertificate, format: 'object' });
    return { ...existing, fingerprint: fp, secret: privateKey.armor(), public: privateKey.toPublic().armor() };
  }

  /* =================================================================
   * 7c. CLEARTEXT SIGNING ("-----BEGIN PGP SIGNED MESSAGE-----")
   * ================================================================= */
  async signCleartext({ text, signerFp }) {
    const signingKeys = await this.requireUnlocked(signerFp);
    return openpgp.sign({ message: await openpgp.createCleartextMessage({ text }), signingKeys });
  }

  async peek(text) {
    try {
      const k = await openpgp.readKey({ armoredKey: text });
      return { fingerprint: k.getFingerprint().toUpperCase(), userIds: k.getUserIDs(), emails: emailsOf(k), inKeyring: this.publicKeys.has(k.getFingerprint().toUpperCase()), key: k };
    } catch { return null; }
  }
}

/* =================================================================
 * 8. HELPERS
 * ================================================================= */
export function emailsOf(key) {
  return key.getUserIDs()
    .map(u => { const m = u.match(/<([^>]+)>/); return (m ? m[1] : u).trim().toLowerCase(); })
    .filter(e => e.includes('@'));
}
