/* =====================================================================
 * Sealpost — mail.js
 * ---------------------------------------------------------------------
 * IMAP (reading) and SMTP (sending).
 *
 * Sections:
 *   1. Connections   — one IMAP connection per account, reconnects
 *   2. Folders       — list with unread counts
 *   3. Message list  — paging, search, PGP badges from body structure
 *   4. Single message— download, mark read, hand off to reader.js
 *   5. Actions       — flag, read/unread, move, delete
 *   6. Sending       — SMTP send + save copy to Sent
 *   7. Connection test
 * ===================================================================== */

const { ImapFlow } = require('imapflow');
const nodemailer = require('nodemailer');

/* 1.10.0: what the message list needs from the server — the References
 * header is included so replies can be grouped into conversations. */
const SUMMARY_QUERY = { uid: true, envelope: true, flags: true, bodyStructure: true, size: true, internalDate: true, headers: ['references'] };
const msgIds = s => (String(s || '').match(/<[^<>\s]+>/g) || []).map(x => x.slice(1, -1).toLowerCase());

class MailService {
  constructor(store) {
    this.store = store;
    this.clients = new Map(); // accountId -> ImapFlow
    this.watchers = new Map(); // accountId -> push watcher (1.2.0)
    this.onPush = () => {};    // set by main.js: (type, data) => void
  }

  /* =================================================================
   * 1. CONNECTIONS
   * ================================================================= */
  _imapOptions(acc) {
    return {
      host: acc.imapHost,
      port: acc.imapPort,
      secure: acc.imapSecurity === 'ssl',
      doSTARTTLS: acc.imapSecurity === 'starttls' ? true : (acc.imapSecurity === 'none' ? false : undefined),
      auth: { user: acc.username || acc.email, pass: acc.password },
      tls: { rejectUnauthorized: !acc.allowSelfSigned },
      logger: false,
      emitLogs: false,
      connectionTimeout: 20000,
      greetingTimeout: 15000
    };
  }

  async client(accountId) {
    let c = this.clients.get(accountId);
    if (c && c.usable) return c;
    const acc = this.store.getAccount(accountId);
    c = new ImapFlow(this._imapOptions(acc));
    c.on('error', err => console.warn('IMAP error', accountId, err.message));
    c.on('close', () => { if (this.clients.get(accountId) === c) this.clients.delete(accountId); });
    await c.connect();
    this.clients.set(accountId, c);
    return c;
  }

  async disconnect(accountId) {
    const c = this.clients.get(accountId);
    this.clients.delete(accountId);
    if (c) { try { await c.logout(); } catch { /* ignore */ } }
  }

  async disconnectAll() {
    for (const id of [...this.clients.keys()]) await this.disconnect(id);
  }

  // Run fn with the mailbox selected and locked
  async _withBox(accountId, folder, fn) {
    const c = await this.client(accountId);
    const lock = await c.getMailboxLock(folder);
    try { return await fn(c); } finally { lock.release(); }
  }

  /* =================================================================
   * 2. FOLDERS
   * ================================================================= */
  async listFolders(accountId) {
    const c = await this.client(accountId);
    const list = await c.list({ statusQuery: { unseen: true, messages: true } });
    return MailService.folderTree(list.map(f => {
      const noselect = !!(f.flags && (f.flags.has('\\Noselect') || f.flags.has('\\NonExistent')));
      return {
        path: f.path,
        name: f.path.toUpperCase() === 'INBOX' ? 'Inbox' : f.name,
        specialUse: f.specialUse || (f.path.toUpperCase() === 'INBOX' ? '\\Inbox' : null),
        delimiter: f.delimiter,
        noselect,                    // 1.9.1: kept so its subfolders still sit under it
        unseen: f.status ? f.status.unseen : 0,
        total: f.status ? f.status.messages : 0
      };
    }));
  }

  /* ---------- Folder tree (fixed in 1.9.1) ----------
   * Puts every folder directly under its parent, in the order you'd
   * expect: Inbox, Drafts, Sent, … first (each with its own subfolders),
   * then your other folders A–Z, subfolders A–Z under each. Before
   * 1.9.1 the special folders were pulled to the top on their own, so a
   * subfolder of Inbox or Sent — or of a folder the server lists as
   * "\Noselect" — ended up separated from its parent.
   * Input: [{ path, name, delimiter, specialUse, ... }] -> same, ordered,
   * each with depth (0 = top level). */
  static folderTree(items) {
    const order = { '\\Inbox': 0, '\\Drafts': 1, '\\Sent': 2, '\\Flagged': 3, '\\Archive': 4, '\\Junk': 5, '\\Trash': 6 };
    const byPath = new Map(items.map(f => [f.path, f]));
    // nearest listed ancestor ("A/B/C" -> "A/B", or "A" if "A/B" isn't listed)
    const parentOf = f => {
      const d = f.delimiter;
      if (!d) return null;
      let p = f.path;
      for (;;) {
        const i = p.lastIndexOf(d);
        if (i <= 0) return null;
        p = p.slice(0, i);
        if (byPath.has(p)) return p;
      }
    };
    const kids = new Map(), roots = [];
    for (const f of items) {
      const p = parentOf(f);
      // name relative to the parent shown, so "A/B/C" under "A" reads "B/C"
      if (f.delimiter && f.path.toUpperCase() !== 'INBOX') {
        const base = p ? p + f.delimiter : '';
        f.name = f.path.slice(base.length) || f.name;
      }
      if (p) { if (!kids.has(p)) kids.set(p, []); kids.get(p).push(f); } else roots.push(f);
    }
    const byName = (a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base', numeric: true });
    const rank = f => (f.specialUse in order ? order[f.specialUse] : 50);
    roots.sort((a, b) => rank(a) - rank(b) || byName(a, b));
    const out = [];
    const walk = (f, depth) => {
      f.depth = depth;
      out.push(f);
      for (const k of (kids.get(f.path) || []).sort(byName)) walk(k, depth + 1);
    };
    for (const r of roots) walk(r, 0);
    return out;
  }

  async _specialFolder(accountId, use) {
    const c = await this.client(accountId);
    const list = await c.list();
    const f = list.find(x => x.specialUse === use);
    if (f) return f.path;
    const names = {
      '\\Sent': ['Sent', 'Sent Items', 'Sent Messages', 'INBOX.Sent'],
      '\\Trash': ['Trash', 'Deleted Items', 'Deleted Messages', 'INBOX.Trash'],
      '\\Drafts': ['Drafts', 'Draft', 'INBOX.Drafts', 'INBOX/Drafts']
    }[use] || [];
    const byName = list.find(x => names.some(n => x.path.toLowerCase() === n.toLowerCase()));
    return byName ? byName.path : null;
  }

  /* =================================================================
   * 3. MESSAGE LIST
   * ================================================================= */
  async listMessages(accountId, folder, { page = 0, pageSize = 50, search = '' } = {}) {
    return this._withBox(accountId, folder, async c => {
      const total = c.mailbox.exists;
      let uids;
      if (search) {
        uids = await c.search({ or: [{ subject: search }, { from: search }, { to: search }, { body: search }] }, { uid: true }) || [];
      } else {
        if (!total) return { total: 0, messages: [], hasMore: false, uidValidity: String(c.mailbox.uidValidity) };
        const end = total - page * pageSize;
        const start = Math.max(1, end - pageSize + 1);
        if (end < 1) return { total, messages: [], hasMore: false };
        const msgs = [];
        for await (const m of c.fetch(`${start}:${end}`, SUMMARY_QUERY)) {
          msgs.push(this._summary(m));
        }
        msgs.sort((a, b) => b.uid - a.uid);
        return { total, messages: msgs, hasMore: start > 1, uidValidity: String(c.mailbox.uidValidity) };
      }
      // search results: newest first, paged
      uids.sort((a, b) => b - a);
      const slice = uids.slice(page * pageSize, (page + 1) * pageSize);
      const msgs = [];
      if (slice.length) {
        for await (const m of c.fetch(slice.join(','), SUMMARY_QUERY, { uid: true })) {
          msgs.push(this._summary(m));
        }
      }
      msgs.sort((a, b) => b.uid - a.uid);
      return { total: uids.length, messages: msgs, hasMore: uids.length > (page + 1) * pageSize, uidValidity: String(c.mailbox.uidValidity) };
    });
  }

  _summary(m) {
    const env = m.envelope || {};
    const bs = m.bodyStructure || {};
    const type = (bs.type || '').toLowerCase();
    return {
      uid: m.uid,
      subject: env.subject || '(no subject)',
      from: (env.from || []).map(a => ({ name: a.name || '', address: a.address || '' })),
      to: (env.to || []).map(a => ({ name: a.name || '', address: a.address || '' })),
      date: (env.date || m.internalDate || new Date()).toISOString?.() || String(env.date),
      seen: m.flags ? m.flags.has('\\Seen') : false,
      flagged: m.flags ? m.flags.has('\\Flagged') : false,
      answered: m.flags ? m.flags.has('\\Answered') : false,
      size: m.size,
      encrypted: type === 'multipart/encrypted',
      signed: type === 'multipart/signed',
      hasAttachments: hasAttachment(bs),
      // 1.10.0: conversation threading
      messageId: msgIds(env.messageId)[0] || null,
      inReplyTo: msgIds(env.inReplyTo)[0] || null,
      references: msgIds(m.headers ? m.headers.toString('utf8').replace(/\r?\n[ \t]+/g, ' ') : '').slice(-30)
    };
  }

  /* =================================================================
   * 4. SINGLE MESSAGE (raw source)
   * ================================================================= */
  async getRaw(accountId, folder, uid, { markSeen = true } = {}) {
    return this._withBox(accountId, folder, async c => {
      const m = await c.fetchOne(String(uid), { source: true, flags: true }, { uid: true });
      if (!m || !m.source) throw new Error('Message not found (it may have been moved or deleted)');
      if (markSeen && !(m.flags && m.flags.has('\\Seen'))) {
        await c.messageFlagsAdd(String(uid), ['\\Seen'], { uid: true });
      }
      return m.source;
    });
  }

  /* =================================================================
   * 5. ACTIONS
   * ================================================================= */
  // expectUidValidity (1.3.0): a change queued offline is skipped if the server rebuilt the folder meanwhile
  async setFlag(accountId, folder, uids, flag, on, expectUidValidity = null) {
    return this._withBox(accountId, folder, async c => {
      if (expectUidValidity && String(c.mailbox.uidValidity) !== String(expectUidValidity)) return false;
      const set = [].concat(uids).join(',');
      if (on) await c.messageFlagsAdd(set, [flag], { uid: true });
      else await c.messageFlagsRemove(set, [flag], { uid: true });
      return true;
    });
  }

  /** 1.6.0: mark every unread message in a folder as read. Returns the UIDs changed. */
  async markFolderRead(accountId, folder) {
    return this._withBox(accountId, folder, async c => {
      const uids = (await c.search({ seen: false }, { uid: true })) || [];
      // in chunks so very large folders don't make one huge command
      for (let i = 0; i < uids.length; i += 500) await c.messageFlagsAdd(uids.slice(i, i + 500).join(','), ['\\Seen'], { uid: true });
      return uids;
    });
  }

  async move(accountId, folder, uids, target) {
    return this._withBox(accountId, folder, async c => {
      await c.messageMove([].concat(uids).join(','), target, { uid: true });
      return true;
    });
  }

  async remove(accountId, folder, uids) {
    const trash = await this._specialFolder(accountId, '\\Trash');
    return this._withBox(accountId, folder, async c => {
      const set = [].concat(uids).join(',');
      if (trash && trash !== folder) await c.messageMove(set, trash, { uid: true });
      else await c.messageDelete(set, { uid: true }); // already in Trash -> permanent
      return true;
    });
  }

  async createFolder(accountId, pathName) {
    const c = await this.client(accountId);
    await c.mailboxCreate(pathName);
    try { await c.mailboxSubscribe(pathName); } catch { /* some servers don't use subscriptions */ }
    return true;
  }

  /* 1.10.0: rename a folder — also how a folder moves under another one
   * ("Projects" -> "Archive/Projects"). Its subfolders go with it. */
  async renameFolder(accountId, from, to) {
    const c = await this.client(accountId);
    await c.mailboxRename(from, to);
    try { await c.mailboxSubscribe(to); } catch { /* ignore */ }
    return true;
  }

  /* 1.10.0: delete a folder and the messages in it (the screen asks first) */
  async deleteFolder(accountId, folderPath) {
    const c = await this.client(accountId);
    await c.mailboxDelete(folderPath);
    return true;
  }

  /* =================================================================
   * 6. SENDING
   * ================================================================= */
  _smtp(acc) {
    return nodemailer.createTransport({
      host: acc.smtpHost,
      port: acc.smtpPort,
      secure: acc.smtpSecurity === 'ssl',
      requireTLS: acc.smtpSecurity === 'starttls',
      ignoreTLS: acc.smtpSecurity === 'none',
      auth: { user: acc.smtpUsername || acc.username || acc.email, pass: acc.smtpPassword },
      tls: { rejectUnauthorized: !acc.allowSelfSigned },
      connectionTimeout: 20000
    });
  }

  async send(accountId, built) {
    const acc = this.store.getAccount(accountId);
    const transport = this._smtp(acc);
    try {
      await transport.sendMail({ envelope: built.envelope, raw: built.raw });
    } finally {
      transport.close();
    }
    // keep a copy in Sent (many servers, e.g. Gmail, do this themselves)
    let savedToSent = false;
    // Gmail and Outlook/Microsoft 365 file sent mail automatically — avoid duplicates
    const skipSentCopy = /gmail\.com|googlemail\.com|office365\.com|outlook\.com/i.test(acc.imapHost);
    if (!skipSentCopy) {
      try {
        const sent = await this._specialFolder(accountId, '\\Sent');
        if (sent) {
          const c = await this.client(accountId);
          await c.append(sent, built.raw, ['\\Seen']);
          savedToSent = true;
        }
      } catch (e) { console.warn('Could not save to Sent:', e.message); }
    }
    return { messageId: built.messageId, savedToSent };
  }

  async markAnswered(accountId, folder, uid) {
    try { await this.setFlag(accountId, folder, uid, '\\Answered', true); } catch { /* not critical */ }
  }

  /* =================================================================
   * 6b. DRAFTS (added 1.1.0)
   * Drafts are stored in the server's Drafts folder so they survive a
   * crash and show up on other devices. Sealpost encrypts them to your
   * own key (see compose.js buildDraft), so the server can't read them.
   * ================================================================= */
  async draftsFolder(accountId) {
    let f = await this._specialFolder(accountId, '\\Drafts');
    if (!f) {
      const c = await this.client(accountId);
      try { await c.mailboxCreate('Drafts'); } catch { /* may exist with odd flags */ }
      f = 'Drafts';
    }
    return f;
  }

  /** Save (or replace) a draft. Returns { folder, uid }. */
  async saveDraft(accountId, raw, { replaceUid = null, messageId = null } = {}) {
    const folder = await this.draftsFolder(accountId);
    const c = await this.client(accountId);
    const res = await c.append(folder, raw, ['\\Draft', '\\Seen']);
    let uid = res && res.uid ? res.uid : null;
    if (!uid && messageId) {
      // server without UIDPLUS: find the draft we just saved by its Message-ID
      uid = await this._withBox(accountId, folder, async cc => {
        const found = await cc.search({ header: { 'message-id': messageId } }, { uid: true });
        return found && found.length ? Math.max(...found) : null;
      });
    }
    if (replaceUid && replaceUid !== uid) {
      try { await this.deleteDraft(accountId, folder, replaceUid); } catch { /* already gone */ }
    }
    return { folder, uid };
  }

  /** Permanently remove a draft (no Trash copy). */
  async deleteDraft(accountId, folder, uid) {
    if (!uid) return false;
    return this._withBox(accountId, folder, async c => {
      await c.messageDelete(String(uid), { uid: true });
      return true;
    });
  }

  /* =================================================================
   * 8. INSTANT NEW MAIL — IMAP IDLE "push" (added 1.2.0)
   * -----------------------------------------------------------------
   * Each account gets one extra connection that sits on INBOX in IDLE
   * mode. The server tells it the moment mail arrives (or messages are
   * read/deleted elsewhere), and Sealpost updates right away instead of
   * waiting for the next check.
   *
   * States sent to the window:  connecting | live | polling | offline
   *   live     server supports IDLE: instant
   *   polling  server lacks IDLE: library checks quietly (every ~2 min)
   *   offline  connection lost: retries with backoff 5 s ... 5 min
   * ================================================================= */
  startWatch(accountId) {
    let w = this.watchers.get(accountId);
    if (w && !w.stopped) return;
    w = { stopped: false, retry: 0, client: null, timer: null, state: 'connecting' };
    this.watchers.set(accountId, w);
    this._connectWatcher(accountId, w);
  }

  async stopWatch(accountId) {
    const w = this.watchers.get(accountId);
    if (!w) return;
    w.stopped = true;
    clearTimeout(w.timer);
    this.watchers.delete(accountId);
    if (w.client) { try { await w.client.logout(); } catch { try { w.client.close(); } catch { /* ignore */ } } }
  }

  async stopAllWatches() { for (const id of [...this.watchers.keys()]) await this.stopWatch(id); }

  /** Reconnect every watcher now (e.g. after the PC wakes up). */
  restartWatches() {
    for (const [id, w] of this.watchers) {
      clearTimeout(w.timer);
      w.retry = 0;
      if (w.client) { try { w.client.close(); } catch { /* ignore */ } } // 'close' handler reconnects
      else this._connectWatcher(id, w);
    }
  }

  watchStatus() {
    const out = {};
    for (const [id, w] of this.watchers) out[id] = w.state;
    return out;
  }

  _setWatchState(accountId, w, state) {
    if (w.state === state) return;
    w.state = state;
    this.onPush('status', { accId: accountId, state });
  }

  _scheduleReconnect(accountId, w) {
    if (w.stopped) return;
    clearTimeout(w.timer);
    const delay = Math.min(300000, 5000 * Math.pow(2, w.retry++));
    this._setWatchState(accountId, w, 'offline');
    w.timer = setTimeout(() => this._connectWatcher(accountId, w), delay);
  }

  async _connectWatcher(accountId, w) {
    if (w.stopped) return;
    let acc;
    try { acc = this.store.getAccount(accountId); } catch { return this.stopWatch(accountId); }
    this._setWatchState(accountId, w, 'connecting');
    // re-issue IDLE every 10 minutes: some servers/routers silently drop long-idle connections
    const c = new ImapFlow({ ...this._imapOptions(acc), maxIdleTime: 10 * 60 * 1000 });
    w.client = c;
    const keepIdling = () => { if (!w.stopped && c.usable) c.idle().catch(() => { /* reconnect handles it */ }); };

    c.on('error', err => console.warn('Push connection error', accountId, err.message));
    c.on('close', () => { if (w.client === c) { w.client = null; this._scheduleReconnect(accountId, w); } });

    // new message(s) in INBOX
    c.on('exists', info => {
      if (!info || info.count <= info.prevCount) return;
      setImmediate(async () => {
        const messages = [];
        try {
          for await (const m of c.fetch(`${info.prevCount + 1}:${info.count}`, SUMMARY_QUERY)) {
            messages.push(this._summary(m));
          }
        } catch (e) { console.warn('Push fetch failed', e.message); }
        this.onPush('new', { accId: accountId, folder: 'INBOX', messages: messages.filter(m => !m.seen) });
        keepIdling();
      });
    });
    // read / flagged / deleted somewhere else (phone, webmail)
    const changed = () => { this.onPush('changed', { accId: accountId, folder: 'INBOX' }); setImmediate(keepIdling); };
    c.on('expunge', changed);
    c.on('flags', changed);

    try {
      await c.connect();
      await c.mailboxOpen('INBOX');
      w.retry = 0;
      this._setWatchState(accountId, w, c.capabilities.has('IDLE') ? 'live' : 'polling');
      keepIdling();
    } catch (e) {
      console.warn('Push connect failed', accountId, e.message);
      try { c.close(); } catch { /* ignore */ }
      if (w.client === c) { w.client = null; this._scheduleReconnect(accountId, w); }
    }
  }

  /* =================================================================
   * 9. OFFLINE CACHE SYNC (added 1.3.0)
   * -----------------------------------------------------------------
   * Runs on its own connection (so it never blocks what you're doing).
   * For every folder except Junk / Trash / "All Mail":
   *   - detect a rebuilt folder (UIDVALIDITY changed) -> start over
   *   - drop messages deleted on the server
   *   - save summaries + flags for the last N days
   *   - download full messages up to maxSize bytes
   * ================================================================= */
  async _syncClient(accountId) {
    this.syncClients = this.syncClients || new Map();
    let c = this.syncClients.get(accountId);
    if (c && c.usable) return c;
    const acc = this.store.getAccount(accountId);
    c = new ImapFlow(this._imapOptions(acc));
    c.on('error', e => console.warn('Sync connection error', accountId, e.message));
    c.on('close', () => { if (this.syncClients.get(accountId) === c) this.syncClients.delete(accountId); });
    await c.connect();
    this.syncClients.set(accountId, c);
    return c;
  }

  async closeSyncClients() {
    for (const [id, c] of this.syncClients || []) { try { await c.logout(); } catch { /* ignore */ } this.syncClients.delete(id); }
  }

  async syncAccount(accountId, cache, { days = 30, maxSize = 10 * 1024 * 1024, shouldStop = () => false } = {}) {
    const stats = { folders: 0, summaries: 0, bodies: 0, removed: 0 };
    const c = await this._syncClient(accountId);
    const folders = await this.listFolders(accountId); // also refreshes unread counts
    cache.saveFolders(accountId, folders);
    const since = new Date(Date.now() - days * 86400000);

    for (const f of folders) {
      if (f.noselect) continue;   // 1.9.1: a container folder holds no mail of its own
      if (['\\Junk', '\\Trash', '\\All'].includes(f.specialUse)) continue;
      if (shouldStop()) break;
      const lock = await c.getMailboxLock(f.path);
      try {
        const uidValidity = String(c.mailbox.uidValidity);
        let idx = cache.getIndex(accountId, f.path);
        if (idx.uidValidity && idx.uidValidity !== uidValidity) idx = cache.resetFolder(accountId, f.path, uidValidity);

        // messages we have saved that the server no longer has
        const cachedUids = Object.keys(idx.messages).map(Number);
        let still = [];
        if (cachedUids.length) {
          still = (await c.search({ uid: cachedUids.join(',') }, { uid: true })) || [];
          const gone = cachedUids.filter(u => !still.includes(u));
          if (gone.length) { cache.removeUids(accountId, f.path, gone); stats.removed += gone.length; }
        }

        // recent messages + current flags of everything saved
        const recent = (await c.search({ since }, { uid: true })) || [];
        const want = [...new Set([...recent, ...still])];
        const summaries = [];
        if (want.length) {
          for await (const m of c.fetch(want.join(','), SUMMARY_QUERY, { uid: true })) {
            summaries.push(this._summary(m));
          }
        }
        idx = cache.upsertSummaries(accountId, f.path, summaries, uidValidity);
        stats.summaries += summaries.length;

        // full messages (newest first), skipping big ones
        const toGet = summaries.filter(m => recent.includes(m.uid) && !idx.bodies[m.uid] && (m.size || 0) <= maxSize)
          .sort((a, b) => b.uid - a.uid);
        for (const m of toGet) {
          if (shouldStop()) break;
          const full = await c.fetchOne(String(m.uid), { source: true }, { uid: true });
          if (full && full.source) { cache.putBody(accountId, f.path, m.uid, full.source); stats.bodies++; }
        }
        stats.folders++;
      } finally { lock.release(); }
    }
    return stats;
  }

  /* =================================================================
   * 7. CONNECTION TEST (used by the account form)
   * ================================================================= */
  async test(acc) {
    const result = { imap: null, smtp: null };
    try {
      const c = new ImapFlow(this._imapOptions(acc));
      await c.connect();
      await c.logout();
      result.imap = 'OK';
    } catch (e) { result.imap = 'Failed: ' + (e.responseText || e.message); }
    try {
      const t = this._smtp(acc);
      await t.verify();
      t.close();
      result.smtp = 'OK';
    } catch (e) { result.smtp = 'Failed: ' + e.message; }
    return result;
  }
}

/** Was this failure caused by the network (offline, server unreachable)? (1.3.0) */
function isNetworkError(e) {
  if (!e) return false;
  const codes = ['ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN', 'ETIMEDOUT', 'ENETUNREACH', 'EHOSTUNREACH', 'ECONNRESET', 'EPIPE', 'ESOCKET', 'ECONNECTION', 'NoConnection', 'ETIMEOUT'];
  if (codes.includes(e.code)) return true;
  return /ECONNREFUSED|ENOTFOUND|EAI_AGAIN|ETIMEDOUT|ENETUNREACH|EHOSTUNREACH|ECONNRESET|socket|timed? ?out|Connection not available|connection closed|Unexpected close|getaddrinfo/i.test(e.message || '');
}

function hasAttachment(node) {
  if (!node) return false;
  if (node.disposition === 'attachment') return true;
  return (node.childNodes || []).some(hasAttachment);
}

module.exports = { MailService, isNetworkError };
