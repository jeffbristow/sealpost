/* =====================================================================
 * Sealpost Web — settings.js  (added 1.4.0)
 * ---------------------------------------------------------------------
 * Settings, mail accounts and importing a Sealpost backup — all saved
 * to your encrypted vault, so Sealpost on your PCs gets them too.
 *
 * Sections:
 *   1. Show the view
 *   2. Preferences (sign / encrypt defaults, text format, images …)
 *   3. Mail accounts: list, add / edit (with provider presets), test,
 *      delete
 *   4. Import a Sealpost backup (.sealbackup) — opened in this browser
 * ===================================================================== */

import { $, $$, esc, show, toast, dialog, confirmBox, pickFiles } from './ui.js?v=1.10.1';
import { openpgp } from './pgp.js?v=1.10.1';

/* Server settings for common providers (same list as Sealpost on your PC) */
const PRESETS = [
  { id: 'zohopro', label: 'Zoho Mail (paid plans / Workplace)', imapHost: 'imappro.zoho.com', imapPort: 993, imapSecurity: 'ssl', smtpHost: 'smtppro.zoho.com', smtpPort: 465, smtpSecurity: 'ssl', note: 'Enable IMAP access in Zoho Mail settings. With two-factor sign-in, use an application-specific password.' },
  { id: 'zoho', label: 'Zoho Mail (free)', imapHost: 'imap.zoho.com', imapPort: 993, imapSecurity: 'ssl', smtpHost: 'smtp.zoho.com', smtpPort: 465, smtpSecurity: 'ssl', note: 'Enable IMAP access in Zoho Mail settings.' },
  { id: 'gmail', label: 'Gmail / Google Workspace', imapHost: 'imap.gmail.com', imapPort: 993, imapSecurity: 'ssl', smtpHost: 'smtp.gmail.com', smtpPort: 465, smtpSecurity: 'ssl', note: 'Turn on 2-Step Verification, then create an App Password and use it as the password here.' },
  { id: 'outlook', label: 'Outlook.com / Hotmail', imapHost: 'outlook.office365.com', imapPort: 993, imapSecurity: 'ssl', smtpHost: 'smtp-mail.outlook.com', smtpPort: 587, smtpSecurity: 'starttls', note: 'If password sign-in is refused, enable IMAP in Outlook settings and use an app password.' },
  { id: 'yahoo', label: 'Yahoo Mail', imapHost: 'imap.mail.yahoo.com', imapPort: 993, imapSecurity: 'ssl', smtpHost: 'smtp.mail.yahoo.com', smtpPort: 465, smtpSecurity: 'ssl', note: 'Generate an app password in Yahoo Account Security.' },
  { id: 'icloud', label: 'iCloud Mail', imapHost: 'imap.mail.me.com', imapPort: 993, imapSecurity: 'ssl', smtpHost: 'smtp.mail.me.com', smtpPort: 587, smtpSecurity: 'starttls', note: 'Use an app-specific password from appleid.apple.com.' },
  { id: 'fastmail', label: 'Fastmail', imapHost: 'imap.fastmail.com', imapPort: 993, imapSecurity: 'ssl', smtpHost: 'smtp.fastmail.com', smtpPort: 465, smtpSecurity: 'ssl', note: 'Create an app password under Settings > Privacy & Security.' },
  { id: 'cpanel', label: 'cPanel / shared hosting', imapHost: 'mail.yourdomain.com', imapPort: 993, imapSecurity: 'ssl', smtpHost: 'mail.yourdomain.com', smtpPort: 465, smtpSecurity: 'ssl', note: 'Replace yourdomain.com with your domain. Username is usually the full email address.' },
  { id: 'custom', label: 'Other (manual)', imapHost: '', imapPort: 993, imapSecurity: 'ssl', smtpHost: '', smtpPort: 465, smtpSecurity: 'ssl', note: '' }
];
// settings that belong to one PC only — never changed from here
const LOCAL_SETTINGS = ['appLock', 'offline', 'lastBackup', 'shortcutIcon', 'sync'];

export function initSettings(ctx) {
  const { state, keyring, vault } = ctx;
  const now = () => new Date().toISOString();

  /* =================================================================
   * 1. SHOW
   * ================================================================= */
  function showSettings() {
    const s = state.vault.settings;
    $('#stRemote').checked = !!s.loadRemoteImages;
    $('#stSign').checked = !!s.defaultSign;
    $('#stEncrypt').checked = !!s.defaultEncrypt;
    $('#stAttachKey').checked = !!s.attachPublicKey;
    $('#stFormat').value = s.composeFormat === 'rich' ? 'rich' : 'plain';
    $('#stAutoContacts').checked = s.autoAddContacts !== false;
    $('#stCache').value = Number.isFinite(Number(s.passphraseCacheMinutes)) ? Number(s.passphraseCacheMinutes) : 15;
    $('#stPage').value = Number(s.pageSize) || 50;
    renderAccounts();
  }

  /* =================================================================
   * 2. PREFERENCES
   * ================================================================= */
  $('#stSave').addEventListener('click', async () => {
    const data = {
      ...state.vault.settings,
      loadRemoteImages: $('#stRemote').checked,
      defaultSign: $('#stSign').checked,
      defaultEncrypt: $('#stEncrypt').checked,
      attachPublicKey: $('#stAttachKey').checked,
      composeFormat: $('#stFormat').value,
      autoAddContacts: $('#stAutoContacts').checked,
      passphraseCacheMinutes: Math.max(0, Math.min(480, Number($('#stCache').value) || 0)),
      pageSize: Math.max(10, Math.min(200, Number($('#stPage').value) || 50))
    };
    for (const k of LOCAL_SETTINGS) delete data[k];
    try { await ctx.save([{ id: 'settings:main', type: 'settings', data }]); toast('Settings saved — they apply on your PCs too.'); }
    catch (e) { toast(e.message, 'err'); }
  });

  /* =================================================================
   * 3. MAIL ACCOUNTS
   * ================================================================= */
  function renderAccounts() {
    const box = $('#stAccounts');
    const accs = state.vault.accounts;
    box.innerHTML = accs.length ? accs.map(a => `
      <div class="acct-row"><div class="grow"><b>${esc(a.name || a.email)}</b><div class="muted small">${esc(a.email)} · ${esc(a.imapHost)}</div>${(a.aliases || []).length ? `<div class="muted small">Also sends as ${esc(a.aliases.map(x => x.email).join(', '))}</div>` : ''}</div>
        <button class="btn small" data-edit="${esc(a.id)}" type="button">Edit</button></div>`).join('')
      : '<p class="muted">No mail accounts yet.</p>';
    $$('#stAccounts [data-edit]').forEach(b => { b.onclick = () => editAccount(b.dataset.edit); });
  }
  $('#stAddAccount').addEventListener('click', () => editAccount(null));

  const secOpts = v => ['ssl', 'starttls', 'none'].map(x => `<option value="${x}"${x === v ? ' selected' : ''}>${{ ssl: 'SSL/TLS', starttls: 'STARTTLS', none: 'None (not secure)' }[x]}</option>`).join('');

  /* 1.7.0: "Name <email>" or "email" per line -> [{ email, name, signature }]
   * (same tidy-up as Sealpost on your PC: unique, valid, never the account's own) */
  function parseAliases(text, ownEmail, old = []) {
    const prev = new Map((old || []).map(x => [x.email.toLowerCase(), x]));
    const seen = new Set([String(ownEmail).toLowerCase()]);
    const out = [];
    for (const line of String(text || '').split(/\r?\n/).map(l => l.trim()).filter(Boolean)) {
      const m = line.match(/^(.*?)\s*<([^>]+)>\s*$/);
      const email = (m ? m[2] : line).trim(), name = (m ? m[1] : '').replace(/^"|"$/g, '').trim();
      if (!/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(email)) { out.bad = email; continue; }
      if (seen.has(email.toLowerCase())) continue;
      seen.add(email.toLowerCase());
      const p = prev.get(email.toLowerCase());
      out.push({ email, name, signature: p ? p.signature || '' : '' });
    }
    return out;
  }

  async function editAccount(id) {
    const a = id ? state.vault.accounts.find(x => x.id === id) : null;
    const v = a || { name: '', email: '', username: '', imapHost: '', imapPort: 993, imapSecurity: 'ssl', smtpHost: '', smtpPort: 465, smtpSecurity: 'ssl', smtpUsername: '', allowSelfSigned: false, signature: '' };
    const form = () => ({
      name: $('#aName').value.trim(), email: $('#aEmail').value.trim(), username: $('#aUser').value.trim(),
      imapHost: $('#aImapHost').value.trim(), imapPort: Number($('#aImapPort').value) || 993, imapSecurity: $('#aImapSec').value,
      smtpHost: $('#aSmtpHost').value.trim(), smtpPort: Number($('#aSmtpPort').value) || 465, smtpSecurity: $('#aSmtpSec').value,
      smtpUsername: $('#aSmtpUser').value.trim(), allowSelfSigned: $('#aSelf').checked, signature: $('#aSig').value,
      aliases: parseAliases($('#aAliases').value, $('#aEmail').value.trim(), v.aliases),   // 1.7.0
      conversationView: $('#aConv').checked                                                 // 1.8.0
    });
    // a blank password box keeps the saved password
    const passwords = f => {
      const password = $('#aPass').value || (a ? a.password : '');
      const separateSmtp = a && a.smtpPassword && a.smtpPassword !== a.password;
      const smtpPassword = $('#aSmtpPass').value || (separateSmtp ? a.smtpPassword : password);
      return { password, smtpPassword };
    };
    const result = await dialog({
      title: a ? 'Edit account' : 'Add account', wide: true, okText: 'Save account',
      extraText: a ? 'Delete account' : null,
      html: `
        ${a ? '' : `<label for="aPreset">Provider</label><select id="aPreset">${PRESETS.map(p => `<option value="${p.id}">${esc(p.label)}</option>`).join('')}</select><p id="aNote" class="muted small"></p>`}
        <div class="two-col">
          <div><label for="aName">Display name</label><input type="text" id="aName" value="${esc(v.name)}"></div>
          <div><label for="aEmail">Email address</label><input type="text" id="aEmail" value="${esc(v.email)}" spellcheck="false"></div>
          <div><label for="aUser">Username</label><input type="text" id="aUser" value="${esc(v.username)}" placeholder="usually your email address" spellcheck="false"></div>
          <div><label for="aPass">Password / app password</label><input type="password" id="aPass" autocomplete="new-password" placeholder="${a ? '(unchanged)' : ''}"></div>
          <div><label for="aImapHost">IMAP server (receiving)</label><input type="text" id="aImapHost" value="${esc(v.imapHost)}" spellcheck="false"></div>
          <div class="two-col"><div><label for="aImapPort">Port</label><input type="text" id="aImapPort" value="${esc(v.imapPort)}" inputmode="numeric"></div><div><label for="aImapSec">Security</label><select id="aImapSec">${secOpts(v.imapSecurity)}</select></div></div>
          <div><label for="aSmtpHost">SMTP server (sending)</label><input type="text" id="aSmtpHost" value="${esc(v.smtpHost)}" spellcheck="false"></div>
          <div class="two-col"><div><label for="aSmtpPort">Port</label><input type="text" id="aSmtpPort" value="${esc(v.smtpPort)}" inputmode="numeric"></div><div><label for="aSmtpSec">Security</label><select id="aSmtpSec">${secOpts(v.smtpSecurity)}</select></div></div>
          <div><label for="aSmtpUser">SMTP username (if different)</label><input type="text" id="aSmtpUser" value="${esc(v.smtpUsername || '')}" spellcheck="false"></div>
          <div><label for="aSmtpPass">SMTP password (if different)</label><input type="password" id="aSmtpPass" autocomplete="new-password"></div>
        </div>
        <label class="check" style="margin-top:10px"><input type="checkbox" id="aSelf" ${v.allowSelfSigned ? 'checked' : ''}> Accept self-signed certificates (local servers only)</label>
        <label class="check"><input type="checkbox" id="aConv" ${v.conversationView ? 'checked' : ''}> Conversation view — group replies with the message they answer (this account only)</label>
        <label for="aSig">Signature (added to new messages)</label><textarea id="aSig" rows="3">${esc(v.signature || '')}</textarea>
        <label for="aAliases">"Send as" addresses (optional, one per line)</label>
        <textarea id="aAliases" rows="3" spellcheck="false" placeholder="Your Name <you@example.com>">${esc((v.aliases || []).map(x => x.name ? `${x.name} <${x.email}>` : x.email).join('\n'))}</textarea>
        <p class="muted small">Other addresses this mailbox may send from — e.g. Zoho Mail → Settings → Mail Accounts → "Send mail as". Set them up there first; they then appear in the From list.</p>
        <div class="row-btns"><button class="btn small" id="aTest" type="button">Test connection</button><span id="aResult" class="small muted"></span></div>
        <p id="aErr" class="error"></p>`,
      onOk: async () => {
        const f = form();
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(f.email)) { $('#aErr').textContent = 'Enter the email address.'; return false; }
        if (!f.imapHost || !f.smtpHost) { $('#aErr').textContent = 'Enter the IMAP and SMTP servers.'; return false; }
        if (f.aliases.bad) { $('#aErr').textContent = `"${f.aliases.bad}" in "Send as" isn't an email address.`; return false; }
        const pw = passwords(f);
        if (!pw.password) { $('#aErr').textContent = 'Enter the password.'; return false; }
        if (!a && state.vault.accounts.some(x => (x.email + '|' + x.imapHost).toLowerCase() === (f.email + '|' + f.imapHost).toLowerCase())) { $('#aErr').textContent = 'This account is already set up.'; return false; }
        const aid = a ? a.id : crypto.randomUUID();
        const data = { ...(a || {}), ...f, id: aid, username: f.username || f.email, ...pw };
        try { await ctx.save([{ id: 'account:' + aid, type: 'account', data }]); return 'saved'; }
        catch (e) { $('#aErr').textContent = e.message; return false; }
      }
    }).then(r => r);

    if (result === 'saved') { toast(a ? 'Account saved.' : 'Account added — it appears on your PCs too.'); renderAccounts(); ctx.loadAccounts(); }
    if (result === 'extra' && a) {
      if (!(await confirmBox('Delete account', `Remove ${a.email} from Sealpost on all your devices? Your mail stays on the mail server.`, 'Delete', true))) return;
      try { await ctx.save([{ id: 'account:' + a.id, type: 'account', data: null }]); toast('Account removed.'); renderAccounts(); ctx.loadAccounts(); }
      catch (e) { toast(e.message, 'err'); }
    }
  }

  // provider presets + the Test button live inside the dialog
  document.addEventListener('change', e => {
    if (e.target.id !== 'aPreset') return;
    const p = PRESETS.find(x => x.id === e.target.value);
    if (!p) return;
    $('#aImapHost').value = p.imapHost; $('#aImapPort').value = p.imapPort; $('#aImapSec').value = p.imapSecurity;
    $('#aSmtpHost').value = p.smtpHost; $('#aSmtpPort').value = p.smtpPort; $('#aSmtpSec').value = p.smtpSecurity;
    $('#aNote').textContent = p.note;
  });
  document.addEventListener('click', async e => {
    if (e.target.id !== 'aTest') return;
    const id = (state.vault.accounts.find(x => x.email === $('#aEmail').value.trim()) || {}).id;
    const a = id ? state.vault.accounts.find(x => x.id === id) : null;
    const pass = $('#aPass').value || (a ? a.password : '');
    const smtpPass = $('#aSmtpPass').value || (a && a.smtpPassword && a.smtpPassword !== a.password ? a.smtpPassword : pass);
    const user = $('#aUser').value.trim() || $('#aEmail').value.trim();
    const self = $('#aSelf').checked;
    $('#aResult').textContent = 'Testing receiving (IMAP)…';
    try {
      await vault.mail('test', { account: { host: $('#aImapHost').value.trim(), port: Number($('#aImapPort').value), security: $('#aImapSec').value, username: user, password: pass, allowSelfSigned: self } });
      $('#aResult').textContent = '✔ Receiving works. Testing sending (SMTP)…';
      await vault.mail('smtpTest', { account: { host: $('#aSmtpHost').value.trim(), port: Number($('#aSmtpPort').value), security: $('#aSmtpSec').value, username: $('#aSmtpUser').value.trim() || user, password: smtpPass, allowSelfSigned: self } });
      $('#aResult').textContent = '✔ Receiving and sending both work.';
    } catch (err) { $('#aResult').textContent = '✖ ' + err.message; }
  });

  /* =================================================================
   * 4. IMPORT A SEALPOST BACKUP
   *    The file is opened in this browser with its backup passphrase;
   *    what's missing from your vault is added (nothing is deleted or
   *    overwritten), then everything syncs to your PCs.
   * ================================================================= */
  $('#stImportBackup').addEventListener('click', async () => {
    const [file] = await pickFiles({ multiple: false, accept: '.sealbackup,.gpg,.pgp' });
    if (!file) return;
    const payload = await dialog({
      title: 'Import a backup',
      html: `<p>File: <b>${esc(file.filename)}</b></p><label for="bkPass">Backup passphrase</label><input type="password" id="bkPass"><p id="bkErr" class="error"></p>`,
      okText: 'Open backup',
      onOk: async () => {
        $('#bkErr').textContent = 'Decrypting…';
        try { return await readBackup(file.bytes, $('#bkPass').value); }
        catch (e) { $('#bkErr').textContent = e.message; return false; }
      }
    });
    if (!payload) return;
    const ks = payload.keyring.keys || [];
    const go = await dialog({
      title: 'Import a backup',
      html: `<div class="restore-summary">Backup from <b>${esc(new Date(payload.created).toLocaleString())}</b> (Sealpost ${esc(payload.appVersion || '?')})
          <ul><li>${payload.accounts.length} account(s): ${esc(payload.accounts.map(a => a.email).join(', ') || '—')}</li>
          <li>${ks.filter(k => k.secret).length} secret key(s), ${ks.length} key(s) in total</li>
          <li>${payload.contacts.length} contact(s)</li></ul></div>
        <p class="small">Importing <b>adds</b> what isn't in your vault yet. Nothing is deleted; accounts and contacts you already have stay as they are. Everything then syncs to your PCs.</p>
        <label class="check"><input type="checkbox" id="bkSettings"> Also use the backup's settings (sign / encrypt defaults etc.)</label>`,
      okText: 'Import'
    });
    if (!go) return;
    try {
      const res = await importBackup(payload, { settings: $('#bkSettings') ? $('#bkSettings').checked : false });
      await dialog({
        title: 'Import complete', hideCancel: true, okText: 'Close',
        html: `<ul><li>Accounts added: ${res.accounts.length ? esc(res.accounts.join(', ')) : 'none'}${res.accountsSkipped.length ? ` (already there: ${esc(res.accountsSkipped.join(', '))})` : ''}</li>
          <li>Keys added or updated: ${res.keys} (${res.secret} secret)</li>
          <li>Contacts added: ${res.contacts}${res.contactsSkipped ? ` (${res.contactsSkipped} already there)` : ''}</li>
          <li>Settings ${res.settings ? 'imported' : 'kept as they were'}</li></ul>
          ${res.errors.length ? `<p class="error">${res.errors.map(esc).join('<br>')}</p>` : ''}`
      });
      ctx.loadAccounts();
      showSettings();
    } catch (e) { toast('Import failed: ' + e.message, 'err'); }
  });

  /** .sealbackup = OpenPGP message encrypted with the backup passphrase; inside, one JSON document. */
  async function readBackup(bytes, passphrase) {
    let message;
    try { message = await openpgp.readMessage({ binaryMessage: bytes }); }
    catch {
      try { message = await openpgp.readMessage({ armoredMessage: new TextDecoder().decode(bytes) }); }
      catch { throw new Error('This is not a Sealpost backup file'); }
    }
    let text;
    try { text = (await openpgp.decrypt({ message, passwords: [passphrase], format: 'utf8' })).data; }
    catch (e) { throw new Error(/modification|integrity|MDC|authentication/i.test(e.message) ? 'The backup file is damaged or was modified' : 'Wrong backup passphrase'); }
    let p;
    try { p = JSON.parse(text); } catch { throw new Error('The backup file is damaged'); }
    if (p.format !== 'sealpost-backup') throw new Error('This is not a Sealpost backup file');
    if (p.version > 1) throw new Error('This backup was made by a newer Sealpost');
    p.accounts = p.accounts || []; p.contacts = p.contacts || []; p.keyring = p.keyring || { keys: [], meta: {} };
    return p;
  }

  async function importBackup(p, opts) {
    const res = { accounts: [], accountsSkipped: [], keys: 0, secret: 0, contacts: 0, contactsSkipped: 0, settings: false, errors: [] };
    const changes = [];
    const keyFps = new Set(keyring.publicKeys.keys());

    // keys (secret keys stay protected by their own passphrases)
    for (const k of p.keyring.keys || []) {
      try {
        const fp = String(k.fingerprint || '').toUpperCase();
        const existing = (state.vault.items.get('key:' + fp) || {}).data || null;
        let data = existing ? { ...existing } : { fingerprint: fp, public: null, secret: null, revocation: null, trust: null };
        if (k.public) {
          const [pub] = await keyring.read(k.public);
          data = { ...data, ...(await keyring.importData(pub, data)) };
        }
        if (k.secret) {
          const [sec] = await keyring.read(k.secret);
          if (!data.secret) { data.secret = (await keyring.importData(sec, data)).secret; res.secret++; }
          data.trust = 'ultimate';
        }
        if (k.revocation && !data.revocation) data.revocation = k.revocation;
        const metaTrust = p.keyring.meta && p.keyring.meta[fp] && p.keyring.meta[fp].trust;
        if (!data.trust && metaTrust) data.trust = metaTrust;
        if (JSON.stringify(data) !== JSON.stringify(existing)) { changes.push({ id: 'key:' + fp, type: 'key', data }); res.keys++; }
        keyFps.add(fp);
      } catch (e) { res.errors.push(`Key ${String(k.fingerprint).slice(-16)}: ${e.message}`); }
    }

    // accounts (skip ones already set up)
    const have = new Set(state.vault.accounts.map(a => (a.email + '|' + a.imapHost).toLowerCase()));
    const ids = new Set(state.vault.accounts.map(a => a.id));
    for (const a of p.accounts) {
      const key = (a.email + '|' + a.imapHost).toLowerCase();
      if (have.has(key)) { res.accountsSkipped.push(a.email); continue; }
      const id = a.id && !ids.has(a.id) ? a.id : crypto.randomUUID();
      changes.push({ id: 'account:' + id, type: 'account', data: { ...a, id } });
      have.add(key); ids.add(id); res.accounts.push(a.email);
    }

    // contacts (skip if any address already belongs to a contact)
    const taken = new Set(state.vault.contacts.flatMap(c => c.emails || []));
    const cids = new Set(state.vault.contacts.map(c => c.id));
    for (const c of p.contacts) {
      const emails = (c.emails || []).map(e => String(e).toLowerCase());
      if (!emails.length || emails.some(e => taken.has(e))) { res.contactsSkipped++; continue; }
      const id = c.id && !cids.has(c.id) ? c.id : crypto.randomUUID();
      const keyFp = c.keyFp && keyFps.has(String(c.keyFp).toUpperCase()) ? String(c.keyFp).toUpperCase() : null;
      changes.push({ id: 'contact:' + id, type: 'contact', data: { ...c, id, emails, keyFp, updated: now() } });
      emails.forEach(e => taken.add(e)); cids.add(id); res.contacts++;
    }

    // settings (optional; the per-PC ones never)
    if (opts.settings && p.settings) {
      const data = { ...state.vault.settings, ...p.settings };
      for (const k of LOCAL_SETTINGS) delete data[k];
      changes.push({ id: 'settings:main', type: 'settings', data });
      res.settings = true;
    }
    if (changes.length) await ctx.save(changes);
    return res;
  }

  return { showSettings };
}
