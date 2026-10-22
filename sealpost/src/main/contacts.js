/* =====================================================================
 * Sealpost — contacts.js   (added 1.1.0)
 * ---------------------------------------------------------------------
 * Contact manager. Stored in <userData>/contacts.json.
 *
 * A contact:
 *   {
 *     id, name, emails: [..],
 *     keyFp:   fingerprint of the public key assigned ("pinned") to this
 *              contact, or null. A pinned key is always used for this
 *              contact, even if a different key for the same address
 *              shows up later — that situation raises a warning instead.
 *     encrypt: 'auto'   (follow the global setting) | 'always'
 *     sign:    'auto' | 'always' | 'never'
 *     notes, created, updated
 *   }
 *
 * Sections:
 *   1. Load / save
 *   2. Lookup helpers (by email, autocomplete)
 *   3. Create / update / delete
 *   4. Key assignment
 * ===================================================================== */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const norm = e => String(e || '').trim().toLowerCase();

class ContactStore {
  constructor(dataDir) {
    this.file = path.join(dataDir, 'contacts.json');
    this.list = [];
    this.load();
  }

  /* =================================================================
   * 1. LOAD / SAVE
   * ================================================================= */
  load() {
    try { this.list = JSON.parse(fs.readFileSync(this.file, 'utf8')); } catch { this.list = []; }
    if (!Array.isArray(this.list)) this.list = [];
  }

  _save() {
    const tmp = this.file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(this.list, null, 2));
    fs.renameSync(tmp, this.file);
  }

  /* =================================================================
   * 2. LOOKUP HELPERS
   * ================================================================= */
  all() {
    return [...this.list].sort((a, b) => (a.name || a.emails[0] || '').localeCompare(b.name || b.emails[0] || ''));
  }

  get(id) { return this.list.find(c => c.id === id) || null; }

  byEmail(email) {
    const e = norm(email);
    return this.list.find(c => c.emails.includes(e)) || null;
  }

  /** Fingerprint pinned for this address, or null. */
  pinnedFor(email) {
    const c = this.byEmail(email);
    return c && c.keyFp ? c.keyFp : null;
  }

  /** Autocomplete: contacts whose name or address contains the text. */
  search(q, limit = 8) {
    q = norm(q);
    if (!q) return [];
    const out = [];
    for (const c of this.all()) {
      for (const e of c.emails) {
        if ((c.name || '').toLowerCase().includes(q) || e.includes(q)) out.push({ contactId: c.id, name: c.name, email: e, keyFp: c.keyFp });
      }
      if (out.length >= limit) break;
    }
    return out.slice(0, limit);
  }

  /* =================================================================
   * 3. CREATE / UPDATE / DELETE
   * ================================================================= */
  save(input) {
    const emails = [...new Set((input.emails || []).map(norm).filter(e => e.includes('@')))];
    if (!emails.length) throw new Error('A contact needs at least one email address');

    // an address can belong to only one contact
    for (const e of emails) {
      const other = this.byEmail(e);
      if (other && other.id !== input.id) throw new Error(`${e} already belongs to contact "${other.name || other.emails[0]}"`);
    }

    const now = new Date().toISOString();
    let c = input.id ? this.get(input.id) : null;
    if (!c) {
      c = { id: crypto.randomUUID(), created: now };
      this.list.push(c);
    }
    Object.assign(c, {
      name: String(input.name || '').trim(),
      emails,
      keyFp: input.keyFp ? String(input.keyFp).toUpperCase() : (input.keyFp === null ? null : c.keyFp || null),
      encrypt: ['auto', 'always'].includes(input.encrypt) ? input.encrypt : (c.encrypt || 'auto'),
      sign: ['auto', 'always', 'never'].includes(input.sign) ? input.sign : (c.sign || 'auto'),
      notes: String(input.notes || ''),
      updated: now
    });
    this._save();
    return c;
  }

  delete(id) {
    this.list = this.list.filter(c => c.id !== id);
    this._save();
  }

  /**
   * Store a contact exactly as it arrived from Sync (1.4.0): same id,
   * same fields. If another contact here already uses one of its
   * addresses, that address moves to the incoming contact (a contact
   * left with no addresses is removed).
   */
  applyRemote(input) {
    const emails = [...new Set((input.emails || []).map(norm).filter(e => e.includes('@')))];
    if (!emails.length || !input.id) return null;
    const now = new Date().toISOString();
    for (const o of this.list) {
      if (o.id === input.id) continue;
      const kept = o.emails.filter(e => !emails.includes(e));
      if (kept.length !== o.emails.length) { o.emails = kept; o.updated = now; }
    }
    this.list = this.list.filter(o => o.id === input.id || o.emails.length);
    let c = this.get(input.id);
    if (!c) { c = { id: input.id }; this.list.push(c); }
    Object.assign(c, {
      name: String(input.name || ''),
      emails,
      keyFp: input.keyFp ? String(input.keyFp).toUpperCase() : null,
      encrypt: ['auto', 'always'].includes(input.encrypt) ? input.encrypt : 'auto',
      sign: ['auto', 'always', 'never'].includes(input.sign) ? input.sign : 'auto',
      notes: String(input.notes || ''),
      created: input.created || c.created || now,
      updated: input.updated || now
    });
    this._save();
    return c;
  }

  /** Create a contact for an address if none exists (used when adding from mail). */
  ensure(email, name) {
    const existing = this.byEmail(email);
    if (existing) return existing;
    return this.save({ name: name || '', emails: [email] });
  }

  /* =================================================================
   * 4. KEY ASSIGNMENT
   * ================================================================= */
  pinKey(id, fp) {
    const c = this.get(id);
    if (!c) throw new Error('Contact not found');
    c.keyFp = fp ? fp.toUpperCase() : null;
    c.updated = new Date().toISOString();
    this._save();
    return c;
  }

  /** When a key is deleted from the keyring, un-assign it everywhere. */
  forgetKey(fp) {
    let changed = false;
    for (const c of this.list) if (c.keyFp === fp) { c.keyFp = null; changed = true; }
    if (changed) this._save();
  }
}

module.exports = { ContactStore, norm };
