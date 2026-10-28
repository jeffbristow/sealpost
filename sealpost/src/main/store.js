/* =====================================================================
 * Sealpost — store.js
 * ---------------------------------------------------------------------
 * Persistent settings and account storage.
 *
 *  - Accounts and settings live in <userData>/sealpost.json
 *  - Account passwords are NEVER written in plain text. When running
 *    inside Electron they are encrypted with safeStorage, which on
 *    Windows 11 uses DPAPI (tied to your Windows login) and on Linux
 *    the login keyring (GNOME Keyring / KDE Wallet). Without a keyring
 *    they are only scrambled, in a file only your user can read (1.8.0).
 * ===================================================================== */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class Store {
  /**
   * @param {string} dataDir   folder to keep sealpost.json in
   * @param {object} [secure]  { encrypt(str)->base64, decrypt(base64)->str }
   */
  constructor(dataDir, secure) {
    this.dataDir = dataDir;
    this.file = path.join(dataDir, 'sealpost.json');
    this.secure = secure || null;
    fs.mkdirSync(dataDir, { recursive: true });
    this.data = this._load();
    this._upgradeProtection();
  }

  /* 1.8.0: passwords saved while no secure storage was available (e.g. a
   * Linux desktop without a login keyring yet) are re-saved encrypted as
   * soon as secure storage is there. */
  _upgradeProtection() {
    if (!this.secure) return;
    let changed = false;
    for (const a of this.data.accounts || []) {
      for (const f of ['password', 'smtpPassword']) {
        if (typeof a[f] === 'string' && a[f].startsWith('b64:')) {
          try { a[f] = this._protect(this._unprotect(a[f])); changed = true; } catch { /* leave as is */ }
        }
      }
    }
    if (changed) this._save();
  }

  /* ---------- Section: load / save the JSON file ---------- */
  _load() {
    const empty = {
      accounts: [],
      settings: {
        loadRemoteImages: false,      // block tracking pixels by default
        passphraseCacheMinutes: 15,   // how long an unlocked key stays unlocked
        defaultEncrypt: false,
        defaultSign: true,
        attachPublicKey: false,
        pageSize: 50
      }
    };
    try {
      const raw = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      return { ...empty, ...raw, settings: { ...empty.settings, ...(raw.settings || {}) } };
    } catch {
      return empty;
    }
  }

  _save() {
    // write to temp file then rename, so a crash can't corrupt the store
    const tmp = this.file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(this.data, null, 2), { encoding: 'utf8', mode: 0o600 });   // 1.8.0: only you can read it (Linux/Mac)
    fs.renameSync(tmp, this.file);
  }

  /* ---------- Section: password protection ---------- */
  _protect(plain) {
    if (!plain) return '';
    if (this.secure) return 'enc:' + this.secure.encrypt(plain);
    return 'b64:' + Buffer.from(plain, 'utf8').toString('base64'); // test mode only
  }

  _unprotect(stored) {
    if (!stored) return '';
    if (stored.startsWith('enc:') && this.secure) return this.secure.decrypt(stored.slice(4));
    if (stored.startsWith('b64:')) return Buffer.from(stored.slice(4), 'base64').toString('utf8');
    return '';
  }

  /* ---------- Section: settings ---------- */
  getSettings() { return { ...this.data.settings }; }

  setSettings(patch) {
    this.data.settings = { ...this.data.settings, ...patch };
    this._save();
    return this.getSettings();
  }

  /* ---------- Section: accounts ---------- */

  /* 1.9.0: tidy a "Send as" list — valid, unique addresses, never the account's own */
  static cleanAliases(list, ownEmail) {
    const seen = new Set([String(ownEmail || '').trim().toLowerCase()]);
    const out = [];
    for (const x of list || []) {
      const email = String((x && x.email) || '').trim();
      const key = email.toLowerCase();
      if (!/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(email) || seen.has(key)) continue;
      seen.add(key);
      out.push({ email, name: String(x.name || '').trim(), signature: String(x.signature || '') });
    }
    return out;
  }

  /** 1.10.0: change an account's folder pins / conversation view without the editor. */
  setAccountPrefs(id, prefs) {
    const a = this.data.accounts.find(x => x.id === id);
    if (!a) throw new Error('Account not found');
    if (Array.isArray(prefs.pinnedFolders)) a.pinnedFolders = [...new Set(prefs.pinnedFolders.map(String).filter(Boolean))].slice(0, 50);
    if (typeof prefs.conversationView === 'boolean') a.conversationView = prefs.conversationView;
    if (prefs.folderIcons && typeof prefs.folderIcons === 'object') a.folderIcons = Store.cleanFolderIcons(prefs.folderIcons);   // 1.13.1
    this._save();
    return this.listAccounts().find(x => x.id === id);
  }

  /** 1.13.1: own folder icons, { folder path: emoji }. */
  static cleanFolderIcons(obj) {
    const out = {};
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return out;
    for (const [p, ic] of Object.entries(obj).slice(0, 200)) {
      const icon = String(ic || '').trim();
      if (p && icon && icon.length <= 16) out[String(p)] = icon;
    }
    return out;
  }

  /** 1.13.1: pins and icons follow a renamed / moved / deleted folder. fn(path) -> new path, or null when it's gone. */
  followFolders(id, fn) {
    const a = this.data.accounts.find(x => x.id === id);
    if (!a) return;
    const pins = (a.pinnedFolders || []).map(fn).filter(p => p != null);
    const icons = {};
    for (const [p, ic] of Object.entries(a.folderIcons || {})) { const q = fn(p); if (q != null) icons[q] = ic; }
    if (JSON.stringify(pins) !== JSON.stringify(a.pinnedFolders || []) || JSON.stringify(icons) !== JSON.stringify(a.folderIcons || {})) {
      this.setAccountPrefs(id, { pinnedFolders: pins, folderIcons: icons });
    }
    // 1.13.2: so does the folder Sealpost opens at start
    const sf = this.data.settings.startFolder;
    if (sf && sf.accId === id && sf.path) {
      const q = fn(sf.path);
      if (q !== sf.path) this.setSettings({ startFolder: q == null ? null : { accId: id, path: q } });
    }
  }

  /** 1.13.2: accounts in the order you arranged them (settings.accountOrder, a list of
   *  account ids). Accounts not in the list keep their place after the others.
   *  Same function in Sealpost Web (web/vault.js) — keep both identical. */
  static orderAccounts(accounts, order) {
    const pos = new Map((Array.isArray(order) ? order : []).map((id, i) => [String(id), i]));
    const at = (a, i) => (pos.has(a.id) ? pos.get(a.id) : pos.size + i);
    return accounts.map((a, i) => [at(a, i), a]).sort((x, y) => x[0] - y[0]).map(x => x[1]);
  }

  /** 1.13.2: tidy the synced start-up choices. accountOrder = [ids];
   *  startFolder = { accId, path } (accId '__all__' = All Inboxes) or null = first account's Inbox. */
  static cleanStartPrefs(patch) {
    const out = { ...patch };
    if ('accountOrder' in out) out.accountOrder = Array.isArray(out.accountOrder) ? [...new Set(out.accountOrder.map(String).filter(Boolean))].slice(0, 100) : [];
    if ('startFolder' in out) {
      const sf = out.startFolder;
      out.startFolder = sf && typeof sf === 'object' && sf.accId && sf.path ? { accId: String(sf.accId), path: String(sf.path) } : null;
    }
    return out;
  }

  // Public list: passwords are stripped before anything reaches the UI
  listAccounts() {
    return Store.orderAccounts(this.data.accounts, this.data.settings.accountOrder).map(a => {   // 1.13.2: your order
      const { password, smtpPassword, ...rest } = a;
      return { ...rest, hasPassword: !!password };
    });
  }

  // Full account including decrypted passwords — main process only
  getAccount(id) {
    const a = this.data.accounts.find(x => x.id === id);
    if (!a) throw new Error('Account not found');
    return {
      ...a,
      password: this._unprotect(a.password),
      smtpPassword: this._unprotect(a.smtpPassword) || this._unprotect(a.password)
    };
  }

  saveAccount(acc) {
    const existing = acc.id ? this.data.accounts.find(x => x.id === acc.id) : null;
    const record = {
      id: acc.id || crypto.randomUUID(),
      name: acc.name || '',
      email: (acc.email || '').trim(),
      imapHost: (acc.imapHost || '').trim(),
      imapPort: Number(acc.imapPort) || 993,
      imapSecurity: acc.imapSecurity || 'ssl',      // ssl | starttls | none
      smtpHost: (acc.smtpHost || '').trim(),
      smtpPort: Number(acc.smtpPort) || 465,
      smtpSecurity: acc.smtpSecurity || 'ssl',
      username: (acc.username || acc.email || '').trim(),
      smtpUsername: (acc.smtpUsername || '').trim(),
      allowSelfSigned: !!acc.allowSelfSigned,       // e.g. Proton Mail Bridge
      signature: acc.signature || '',
      // 1.9.0: other addresses this mailbox may send as (Zoho "Send mail as",
      // Gmail "Send mail as", Outlook aliases…): [{ email, name, signature }]
      aliases: Array.isArray(acc.aliases) ? Store.cleanAliases(acc.aliases, acc.email) : (existing && existing.aliases) || [],
      // 1.10.0: folders pinned to the top of the folder list, and the conversation view switch (off unless turned on)
      pinnedFolders: Array.isArray(acc.pinnedFolders) ? [...new Set(acc.pinnedFolders.map(String).filter(Boolean))].slice(0, 50) : (existing && existing.pinnedFolders) || [],
      conversationView: typeof acc.conversationView === 'boolean' ? acc.conversationView : !!(existing && existing.conversationView),
      // 1.13.1: own folder icons (right-click a folder -> Choose icon…)
      folderIcons: acc.folderIcons && typeof acc.folderIcons === 'object' ? Store.cleanFolderIcons(acc.folderIcons) : (existing && existing.folderIcons) || {},
      // keep old password if the form left the field blank
      password: acc.password ? this._protect(acc.password) : (existing ? existing.password : ''),
      smtpPassword: acc.smtpPassword ? this._protect(acc.smtpPassword) : (existing ? existing.smtpPassword : '')
    };
    if (existing) Object.assign(existing, record);
    else this.data.accounts.push(record);
    this._save();
    return this.listAccounts().find(a => a.id === record.id);
  }

  deleteAccount(id) {
    this.data.accounts = this.data.accounts.filter(a => a.id !== id);
    this._save();
  }
}

module.exports = { Store };
