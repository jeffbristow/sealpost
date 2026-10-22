/* =====================================================================
 * Sealpost — backup.js   (added 1.2.0)
 * ---------------------------------------------------------------------
 * One-file backup and restore of everything Sealpost needs to be set
 * up again on a new PC: accounts (with passwords), settings, contacts,
 * and the whole PGP keyring (your secret keys stay protected by their
 * own passphrases inside the backup as well).
 *
 * File format (.sealbackup)
 *   A standard OpenPGP message encrypted with the backup passphrase
 *   (salted + iterated S2K, AES-256, integrity protected). Inside is
 *   one JSON document. Because it's plain OpenPGP, even without
 *   Sealpost it can be opened with GnuPG / Kleopatra:
 *       gpg --decrypt Sealpost-backup.sealbackup > backup.json
 *
 * Not included on purpose
 *   - "Remember passphrase" entries: they're locked to this Windows
 *     login. Tick "Remember" again on the new PC.
 *   - Messages: they live on your mail server.
 *
 * Sections:
 *   1. Create
 *   2. Read (decrypt + summarize)
 *   3. Restore (merge into the current setup — never deletes anything)
 * ===================================================================== */

const fs = require('fs');
const path = require('path');
const openpgp = require('openpgp');

const FORMAT = 'sealpost-backup';

/* =================================================================
 * 1. CREATE
 * ================================================================= */
async function createBackup({ store, pgp, contacts, appVersion, passphrase }) {
  if (!passphrase || passphrase.length < 10) throw new Error('Use a backup passphrase of at least 10 characters');

  // accounts with their passwords decrypted (they're re-protected on restore)
  const accounts = store.data.accounts.map(a => {
    const full = store.getAccount(a.id);
    return { ...full };
  });

  // keyring: every public key, secret keys (still passphrase-protected), revocation certificates
  const keys = [];
  for (const [fp, key] of pgp.publicKeys) {
    const entry = { fingerprint: fp, public: key.armor(), secret: null, revocation: null };
    if (pgp.privateKeys.has(fp)) entry.secret = pgp.privateKeys.get(fp).armor();
    const rev = path.join(pgp.privDir, fp + '.rev');
    if (fs.existsSync(rev)) entry.revocation = fs.readFileSync(rev, 'utf8');
    keys.push(entry);
  }

  const payload = {
    format: FORMAT, version: 1,
    created: new Date().toISOString(),
    appVersion,
    settings: store.getSettings(),          // includes the app-lock PIN hash (never the PIN)
    accounts,
    contacts: contacts.all(),
    keyring: { meta: pgp.meta, keys }
  };

  const message = await openpgp.createMessage({ text: JSON.stringify(payload) });
  const encrypted = await openpgp.encrypt({
    message,
    passwords: [passphrase],
    format: 'binary',
    config: {
      preferredSymmetricAlgorithm: openpgp.enums.symmetric.aes256,
      preferredCompressionAlgorithm: openpgp.enums.compression.zlib,
      s2kIterationCountByte: 255            // slowest standard setting: makes guessing the passphrase expensive
    }
  });
  return {
    data: Buffer.from(encrypted),
    summary: summarize(payload)
  };
}

/* =================================================================
 * 2. READ
 * ================================================================= */
async function readBackup(fileBuffer, passphrase) {
  let message;
  try { message = await openpgp.readMessage({ binaryMessage: new Uint8Array(fileBuffer) }); }
  catch {
    try { message = await openpgp.readMessage({ armoredMessage: fileBuffer.toString('utf8') }); }
    catch { throw new Error('This is not a Sealpost backup file'); }
  }
  let text;
  try {
    const res = await openpgp.decrypt({ message, passwords: [passphrase], format: 'utf8' });
    text = res.data;
  } catch (e) {
    if (/modification|integrity|MDC|authentication/i.test(e.message)) throw new Error('The backup file is damaged or was modified');
    throw new Error('Wrong backup passphrase');
  }
  let payload;
  try { payload = JSON.parse(text); } catch { throw new Error('The backup file is damaged'); }
  if (payload.format !== FORMAT) throw new Error('This is not a Sealpost backup file');
  if (payload.version > 1) throw new Error('This backup was made by a newer Sealpost. Update Sealpost first.');
  return payload;
}

function summarize(p) {
  return {
    created: p.created,
    appVersion: p.appVersion,
    accounts: p.accounts.map(a => a.email),
    secretKeys: p.keyring.keys.filter(k => k.secret).length,
    publicKeys: p.keyring.keys.length,
    contacts: p.contacts.length,
    appLock: !!(p.settings && p.settings.appLock && p.settings.appLock.enabled)
  };
}

/* =================================================================
 * 3. RESTORE — merges; nothing already on this PC is deleted
 * ================================================================= */
async function restoreBackup(payload, { store, pgp, contacts }, { restoreSettings = true } = {}) {
  const result = { accountsAdded: [], accountsSkipped: [], keysImported: 0, keysUpdated: 0, secretKeys: 0, contactsAdded: 0, contactsSkipped: 0, settings: false, errors: [] };

  /* ---- keys first, so contacts can point at them ---- */
  for (const k of payload.keyring.keys) {
    try {
      if (k.secret) {
        const r = await pgp.importKeys(k.secret);
        result.secretKeys += r.secret.length;
      }
      const r = await pgp.importKeys(k.public);
      result.keysImported += r.imported.length;
      result.keysUpdated += r.updated.length;
      if (k.revocation) {
        const rev = path.join(pgp.privDir, k.fingerprint + '.rev');
        if (!fs.existsSync(rev) && pgp.privateKeys.has(k.fingerprint)) fs.writeFileSync(rev, k.revocation);
      }
    } catch (e) { result.errors.push(`Key ${k.fingerprint.slice(-16)}: ${e.message}`); }
  }
  // trust levels (only for keys that don't already have one here)
  for (const [fp, m] of Object.entries(payload.keyring.meta || {})) {
    if (!pgp.meta[fp] && pgp.publicKeys.has(fp)) pgp.meta[fp] = m;
  }
  pgp._saveMeta();

  /* ---- accounts (skip ones already set up here) ---- */
  const existing = store.data.accounts.map(a => (a.email + '|' + a.imapHost).toLowerCase());
  for (const a of payload.accounts) {
    const id = (a.email + '|' + a.imapHost).toLowerCase();
    if (existing.includes(id)) { result.accountsSkipped.push(a.email); continue; }
    try {
      store.saveAccount({ ...a }); // passwords get protected with THIS PC's Windows login
      result.accountsAdded.push(a.email);
    } catch (e) { result.errors.push(`Account ${a.email}: ${e.message}`); }
  }

  /* ---- contacts (skip if any of their addresses already belongs to a contact) ---- */
  for (const c of payload.contacts) {
    if (c.emails.some(e => contacts.byEmail(e))) { result.contactsSkipped++; continue; }
    try {
      const { id, ...rest } = c;
      if (rest.keyFp && !pgp.publicKeys.has(rest.keyFp)) rest.keyFp = null;
      contacts.save(rest);
      result.contactsAdded++;
    } catch (e) { result.errors.push(`Contact ${c.emails[0]}: ${e.message}`); }
  }

  /* ---- settings (optional) ---- */
  if (restoreSettings && payload.settings) {
    // offline cache is per-PC (locked to the PIN set up here) — not carried over (1.3.0)
    const { lastBackup, offline, ...s } = payload.settings;
    store.setSettings(s);
    result.settings = true;
  }
  return result;
}

module.exports = { createBackup, readBackup, restoreBackup, summarize };
