/* =====================================================================
 * Sealpost Web — people.js  (Contacts + Keys)
 * ---------------------------------------------------------------------
 * Everything you change here is saved to your encrypted vault and syncs
 * to Sealpost on your PCs (and back).
 *
 * Sections:
 *   1. Contacts: list, search, edit, assign a key, rules, delete
 *   2. Adding a contact from a message
 *   3. Keys: list, details, trust, copy / download, delete
 *   4. "Remember passphrase on all my devices"
 *   5. Importing keys (paste, file, from a message)
 *   6. Generating a key pair
 *   7. Key upkeep: extend expiry, change passphrase, revoke, publish (1.4.0)
 *   8. Finding keys online (WKD + keys.openpgp.org, through your server) (1.4.0)
 * ===================================================================== */

import { $, $$, esc, show, toast, dialog, confirmBox, download, copyText, pickFiles, promptPassphrase } from './ui.js?v=1.11.1';

export function initPeople(ctx) {
  const { state, keyring } = ctx;
  let selContact = null, selKey = null;
  const now = () => new Date().toISOString();
  const keyItem = fp => { const e = state.vault.items.get('key:' + fp); return e ? e.data : null; };

  /* =================================================================
   * 1. CONTACTS
   * ================================================================= */
  function showContacts() {
    const q = $('#contactFilter').value.trim().toLowerCase();
    const list = [...state.vault.contacts]
      .filter(c => !q || (c.name || '').toLowerCase().includes(q) || (c.emails || []).some(e => e.includes(q)))
      .sort((a, b) => (a.name || a.emails[0] || '').localeCompare(b.name || b.emails[0] || ''));
    $('#contactCount').textContent = state.vault.contacts.length ? `(${state.vault.contacts.length})` : '';
    $('#contactList').innerHTML = list.length ? list.map(c => `
      <div class="msg${c.id === selContact ? ' active' : ''}" data-id="${esc(c.id)}" role="button">
        <div class="top"><span class="from" style="color:var(--text)">${esc(c.name || c.emails[0])}</span>${c.keyFp ? '<span class="badge enc" title="Has an assigned key">🔑</span>' : ''}</div>
        <div class="subj">${esc((c.emails || []).join(', '))}</div></div>`).join('')
      : `<div class="list-empty">${state.vault.contacts.length ? 'No contacts match.' : 'No contacts yet.'}</div>`;
    if (selContact && !state.vault.contacts.some(c => c.id === selContact)) { selContact = null; $('#contactDetail').innerHTML = ''; }
    if (!selContact && !$('#contactDetail').innerHTML.trim()) $('#contactDetail').innerHTML = '<div class="reader-empty"><p>Select a contact, or add a new one.</p></div>';
  }
  $('#contactFilter').addEventListener('input', showContacts);
  $('#contactList').addEventListener('click', e => { const r = e.target.closest('.msg'); if (r) editContact(r.dataset.id); });
  $('#btnNewContact').addEventListener('click', () => editContact(null));

  function keysFor(emails) {
    const out = [];
    for (const [fp, k] of keyring.publicKeys) {
      const ke = k.getUserIDs().map(u => { const m = u.match(/<([^>]+)>/); return (m ? m[1] : u).toLowerCase(); });
      if (ke.some(e => emails.includes(e))) out.push({ fp, uid: k.getUserIDs()[0] });
    }
    return out;
  }

  function editContact(id) {
    selContact = id;
    showContacts();
    $('#app').classList.add('reading');
    const c = id ? state.vault.contacts.find(x => x.id === id) : { name: '', emails: [], keyFp: null, encrypt: 'auto', sign: 'auto', notes: '' };
    if (!c) return;
    const opts = keysFor(c.emails || []);
    if (c.keyFp && !opts.some(o => o.fp === c.keyFp)) opts.unshift({ fp: c.keyFp, uid: keyring.publicKeys.has(c.keyFp) ? keyring.userIdOf(c.keyFp) : '(key not in your keyring)' });
    $('#contactDetail').innerHTML = `
      <div class="detail-card">
        <div class="reader-actions"><button class="btn small mobile-only" id="ctBack">← Back</button><span class="spacer"></span>
          ${id ? '<button class="btn small" id="ctWrite">✎ Write</button>' : ''}</div>
        <h2>${id ? esc(c.name || c.emails[0]) : 'New contact'}</h2>
        <label for="ctName">Name</label><input type="text" id="ctName" value="${esc(c.name)}">
        <label for="ctEmails">Email addresses (one per line)</label><textarea id="ctEmails" rows="3" spellcheck="false">${esc((c.emails || []).join('\n'))}</textarea>
        <label for="ctKey">PGP key used for this contact</label>
        <select id="ctKey"><option value="">None — use the newest key for their address</option>${opts.map(o => `<option value="${esc(o.fp)}"${o.fp === c.keyFp ? ' selected' : ''}>${esc(o.uid)} · ${esc(o.fp.slice(-16))}</option>`).join('')}</select>
        <p class="muted small">An assigned key is always used for this contact. If a message arrives signed with a different key, Sealpost warns you.</p>
        <div class="two-col">
          <div><label for="ctEnc">Encrypt</label><select id="ctEnc"><option value="auto">Follow my default</option><option value="always">Always encrypt</option></select></div>
          <div><label for="ctSign">Sign</label><select id="ctSign"><option value="auto">Follow my default</option><option value="always">Always sign</option><option value="never">Never sign</option></select></div>
        </div>
        <label for="ctNotes">Notes</label><textarea id="ctNotes" rows="3">${esc(c.notes || '')}</textarea>
        <p id="ctErr" class="error"></p>
        <div class="row-btns"><button class="btn primary" id="ctSave">Save</button>${id ? '<button class="btn danger" id="ctDelete">Delete</button>' : ''}</div>
      </div>`;
    $('#ctEnc').value = c.encrypt || 'auto';
    $('#ctSign').value = c.sign || 'auto';
    $('#ctBack').onclick = () => $('#app').classList.remove('reading');
    if (id) $('#ctWrite').onclick = () => ctx.openComposer({ to: c.name ? `${c.name.replace(/[",<>]/g, '')} <${c.emails[0]}>` : c.emails[0] });
    $('#ctSave').onclick = async () => {
      const emails = [...new Set($('#ctEmails').value.split(/[\s,;]+/).map(e => e.trim().toLowerCase()).filter(e => e.includes('@')))];
      if (!emails.length) { $('#ctErr').textContent = 'A contact needs at least one email address.'; return; }
      for (const e of emails) {
        const other = state.vault.contacts.find(x => x.id !== id && (x.emails || []).includes(e));
        if (other) { $('#ctErr').textContent = `${e} already belongs to "${other.name || other.emails[0]}".`; return; }
      }
      const cid = id || crypto.randomUUID();
      const data = { ...c, id: cid, name: $('#ctName').value.trim(), emails, keyFp: $('#ctKey').value || null, encrypt: $('#ctEnc').value, sign: $('#ctSign').value, notes: $('#ctNotes').value, created: c.created || now(), updated: now() };
      try { await ctx.save([{ id: 'contact:' + cid, type: 'contact', data }]); toast('Contact saved.'); editContact(cid); }
      catch (err) { $('#ctErr').textContent = err.message; }
    };
    if (id) $('#ctDelete').onclick = async () => {
      if (!(await confirmBox('Delete contact', `Delete ${c.name || c.emails[0]}? Their keys stay in your keyring.`, 'Delete', true))) return;
      try { await ctx.save([{ id: 'contact:' + id, type: 'contact', data: null }]); selContact = null; $('#contactDetail').innerHTML = ''; showContacts(); $('#app').classList.remove('reading'); toast('Contact deleted.'); }
      catch (err) { toast(err.message, 'err'); }
    };
  }

  /* =================================================================
   * 2. ADD A CONTACT FROM A MESSAGE (with their key, if you have it)
   * ================================================================= */
  async function addContact({ name, email }) {
    email = email.toLowerCase();
    if (state.vault.contacts.some(c => (c.emails || []).includes(email))) { toast(`${email} is already a contact.`); return; }
    const best = await keyring.bestKeyByEmail(email);
    const id = crypto.randomUUID();
    await ctx.save([{ id: 'contact:' + id, type: 'contact', data: { id, name: name || '', emails: [email], keyFp: best ? best.getFingerprint().toUpperCase() : null, encrypt: 'auto', sign: 'auto', notes: '', created: now(), updated: now() } }]);
    toast(`${name || email} added to your contacts${best ? ' with their key' : ''}.`);
  }

  /* =================================================================
   * 3. KEYS
   * ================================================================= */
  async function showKeys() {
    const q = $('#keyFilter').value.trim().toLowerCase().replace(/\s/g, '');
    const fps = [...keyring.publicKeys.keys()];
    const rows = [];
    for (const fp of fps) {
      const d = await keyring.describe(fp);
      if (q && !d.userIds.join(' ').toLowerCase().replace(/\s/g, '').includes(q) && !fp.toLowerCase().includes(q)) continue;
      rows.push(d);
    }
    rows.sort((a, b) => (b.hasPrivate - a.hasPrivate) || (a.userIds[0] || '').localeCompare(b.userIds[0] || ''));
    $('#keyCount').textContent = fps.length ? `(${fps.length})` : '';
    $('#keyList').innerHTML = rows.length ? rows.map(k => `
      <div class="msg${k.fingerprint === selKey ? ' active' : ''}" data-fp="${esc(k.fingerprint)}" role="button">
        <div class="top"><span class="from" style="color:var(--text)">${esc(k.userIds[0] || '(no user id)')}</span></div>
        <div class="subj"><span class="mono">${esc(k.keyId.replace(/(.{4})/g, '$1 '))}</span> <span class="badges">${badges(k)}</span></div></div>`).join('')
      : `<div class="list-empty">${fps.length ? 'No keys match.' : 'Your keyring is empty. Generate a key pair or import keys.'}</div>`;
    if (selKey && !keyring.publicKeys.has(selKey)) { selKey = null; $('#keyDetail').innerHTML = ''; }
    if (selKey) renderKey(selKey);
    else if (!$('#keyDetail').innerHTML.trim()) $('#keyDetail').innerHTML = '<div class="reader-empty"><p>Select a key to see its details.</p></div>';
  }
  $('#keyFilter').addEventListener('input', showKeys);
  $('#keyList').addEventListener('click', e => { const r = e.target.closest('.msg'); if (r) { selKey = r.dataset.fp; $$('#keyList .msg').forEach(x => x.classList.toggle('active', x === r)); renderKey(selKey); } });

  function badges(k) {
    return [
      k.hasPrivate ? '<span class="badge enc">YOUR KEY</span>' : '<span class="badge plain">PUBLIC</span>',
      k.revoked ? '<span class="badge bad">REVOKED</span>' : '',
      k.expired ? '<span class="badge bad">EXPIRED</span>' : '',
      k.trust === 'verified' ? '<span class="badge sig">✔ VERIFIED</span>' : '',
      k.trust === 'untrusted' ? '<span class="badge bad">DISTRUSTED</span>' : '',
      k.remembered ? '<span class="badge sig">🔑 ALL DEVICES</span>' : '',
      k.hasPrivate && k.unlocked ? '<span class="badge warn">UNLOCKED</span>' : ''
    ].join('');
  }

  async function renderKey(fp) {
    const k = await keyring.describe(fp);
    $('#app').classList.add('reading');
    $('#keyDetail').innerHTML = `
      <div class="detail-card">
        <div class="reader-actions"><button class="btn small mobile-only" id="kBack">← Back</button></div>
        <h2>${esc(k.userIds[0] || '')}</h2>
        <div class="badges">${badges(k)}</div>
        <div class="kv">
          <span class="k">Fingerprint</span><span class="fp">${esc(k.fingerprintPretty)}</span>
          <span class="k">User IDs</span><span>${k.userIds.map(esc).join('<br>')}</span>
          <span class="k">Algorithm</span><span>${esc(k.algorithm)}</span>
          <span class="k">Created</span><span>${esc(new Date(k.created).toLocaleDateString())}</span>
          <span class="k">Expires</span><span>${k.expires ? esc(new Date(k.expires).toLocaleDateString()) + (k.expired ? ' (expired)' : '') : 'Never'}</span>
          <span class="k">Can encrypt / sign</span><span>${k.canEncrypt ? 'Yes' : 'No'} / ${k.canSign ? 'Yes' : 'No'}</span>
          <span class="k">Trust</span><span>${k.hasPrivate ? 'Your own key' : `<select id="kTrust" class="small-select">
            <option value="unknown">Unknown — not checked</option><option value="verified">Verified — I compared the fingerprint</option><option value="untrusted">Do not trust</option></select>`}</span>
        </div>
        <div class="row-btns" id="kActions"></div>
        ${k.hasPrivate ? `<div class="sync-pass">
          <label class="check"><input type="checkbox" id="kRemember" ${k.remembered ? 'checked' : ''}> Remember passphrase on all my devices</label>
          <p class="muted small">Sealpost Web and every Sealpost connected to your vault unlock this key without asking. The passphrase is stored encrypted in your vault — but your vault passphrase alone is then enough to read your encrypted mail.</p>
        </div>` : ''}
        <p class="muted small">Verify a contact's key by comparing the fingerprint with them by phone, in person, or another trusted channel.</p>
      </div>`;
    $('#kBack').onclick = () => $('#app').classList.remove('reading');
    if (!k.hasPrivate) {
      $('#kTrust').value = k.trust;
      $('#kTrust').onchange = async e => {
        try { await ctx.save([{ id: 'key:' + fp, type: 'key', data: { ...(keyItem(fp) || { public: keyring.publicKeys.get(fp).armor(), secret: null, revocation: null }), trust: e.target.value } }]); toast('Trust updated.'); showKeys(); }
        catch (err) { toast(err.message, 'err'); }
      };
    }
    if (k.hasPrivate) $('#kRemember').onchange = e => rememberToggle(k, e.target);
    const acts = $('#kActions');
    const btn = (label, fn, cls = '') => { const b = document.createElement('button'); b.className = 'btn small ' + cls; b.textContent = label; b.onclick = async () => { try { await fn(); } catch (e) { if (e.code !== 'CANCELLED') toast(e.message, 'err'); } }; acts.appendChild(b); };
    const armored = () => keyring.publicKeys.get(fp).armor();
    btn('Copy public key', async () => { await copyText(armored()); toast('Public key copied.'); });
    btn('Download public key', () => download(new TextEncoder().encode(armored()), `${(k.emails[0] || 'key').replace(/[^a-z0-9@._-]/gi, '_')}-${fp.slice(-8)}.asc`, 'application/pgp-keys'));
    if (k.hasPrivate) {
      btn('Send public key by email', () => ctx.openComposer().then(() => { $('#cSubject').value = 'My OpenPGP public key'; $('#cAttachKey').checked = true; }));
      btn(k.unlocked ? 'Lock' : 'Unlock', async () => {
        if (k.unlocked) keyring.unlocked.delete(fp); else await promptPassphrase(keyring, fp, k.userIds[0]);
        showKeys();
      });
      if (!k.revoked) btn('Extend expiry…', () => extendDialog(k));
      btn('Change passphrase…', () => changePassDialog(k));
      btn('Publish to keys.openpgp.org', () => publishKey(k));
      if (!k.revoked && (keyItem(fp) || {}).revocation) btn('Revoke…', () => revokeKey(k), 'danger');
    }
    btn('Delete…', () => deleteKey(k), 'danger');
  }

  async function deleteKey(k) {
    const fp = k.fingerprint;
    const msg = k.hasPrivate
      ? 'This deletes your PRIVATE key from your vault and from every device that syncs with it. You will no longer be able to read messages encrypted to it unless you have a backup. Sealpost on your PCs keeps a copy in keyring\\removed-by-sync, but continue only if you are sure.'
      : 'Remove this public key from your keyring (on all your devices)?';
    if (!(await confirmBox('Delete key', msg, 'Delete', true))) return;
    const changes = [{ id: 'key:' + fp, type: 'key', data: null }];
    if (state.vault.items.has('passphrase:' + fp)) changes.push({ id: 'passphrase:' + fp, type: 'passphrase', data: null });
    for (const c of state.vault.contacts.filter(c => c.keyFp === fp)) changes.push({ id: 'contact:' + c.id, type: 'contact', data: { ...c, keyFp: null, updated: now() } });
    await ctx.save(changes);
    selKey = null; $('#keyDetail').innerHTML = '';
    $('#app').classList.remove('reading');
    toast('Key deleted.');
    showKeys();
  }

  /* =================================================================
   * 4. REMEMBER PASSPHRASE ON ALL MY DEVICES
   * ================================================================= */
  async function rememberToggle(k, box) {
    const fp = k.fingerprint;
    if (!box.checked) {
      try { await ctx.save([{ id: 'passphrase:' + fp, type: 'passphrase', data: null }]); keyring.unlocked.delete(fp); toast('Passphrase removed from your vault. Your devices will ask for it again.'); }
      catch (e) { box.checked = true; toast(e.message, 'err'); }
      return showKeys();
    }
    box.checked = false;
    const ok = await dialog({
      title: 'Remember on all my devices',
      html: `<p>The passphrase for <b>${esc(k.userIds[0] || '')}</b> will be kept in your encrypted vault. Sealpost Web and every Sealpost connected to your vault will then unlock this key automatically.</p>
        <p class="muted small">Your server can't read it. But from now on your <b>vault passphrase alone</b> is enough to read your encrypted mail — make sure it is long and used nowhere else. You can turn this off any time.</p>
        <label for="rpPass">Key passphrase</label><input type="password" id="rpPass"><p id="rpErr" class="error"></p>`,
      okText: 'Remember on all devices',
      onOk: async () => {
        $('#rpErr').textContent = 'Checking…';
        const p = $('#rpPass').value;
        if (!(await keyring.checkPassphrase(fp, p))) { $('#rpErr').textContent = 'That passphrase doesn\'t open this key.'; return false; }
        await ctx.save([{ id: 'passphrase:' + fp, type: 'passphrase', data: { fingerprint: fp, passphrase: p } }]);
        return true;
      }
    });
    if (ok) toast('Saved to your vault — your devices will unlock this key automatically.');
    showKeys();
  }

  /* =================================================================
   * 5. IMPORTING KEYS
   *    importKeys(text | bytes, { from, name }) — from a message: the
   *    key is then assigned to that sender's contact.
   * ================================================================= */
  async function importKeys(input, { from = '', name = '' } = {}) {
    const keys = await keyring.read(input);
    if (!keys.length) throw new Error('No key found.');
    const list = keys.map(k => `<li><b>${esc(k.getUserIDs()[0] || '')}</b> ${k.isPrivate() ? '<span class="badge enc">SECRET KEY</span>' : ''}<div class="fp">${esc(k.getFingerprint().toUpperCase().replace(/(.{4})/g, '$1 '))}</div></li>`).join('');
    const ok = await dialog({
      title: keys.length === 1 ? 'Import key' : `Import ${keys.length} keys`,
      html: `<ul class="key-import">${list}</ul><p class="muted small">Before you rely on a key, compare its fingerprint with the owner (phone, in person). Imported keys sync to all your devices.</p>`,
      okText: 'Import'
    });
    if (!ok) return false;
    const changes = [];
    for (const k of keys) {
      const fp = k.getFingerprint().toUpperCase();
      changes.push({ id: 'key:' + fp, type: 'key', data: await keyring.importData(k, keyItem(fp)) });
    }
    // assign to the sender's contact (create the contact if needed)
    if (from) {
      const f = from.toLowerCase();
      const kf = keyring.keyAddress(f);   // 1.11.0: an addy.io sender's key carries the real address
      const match = keys.find(k => k.getUserIDs().some(u => u.toLowerCase().includes(f) || u.toLowerCase().includes(kf)));
      if (match) {
        const fp = match.getFingerprint().toUpperCase();
        const c = state.vault.contacts.find(x => (x.emails || []).includes(f)) || state.vault.contacts.find(x => (x.emails || []).includes(kf));
        if (c && !c.keyFp) changes.push({ id: 'contact:' + c.id, type: 'contact', data: { ...c, keyFp: fp, updated: now() } });
        if (!c) { const id = crypto.randomUUID(); changes.push({ id: 'contact:' + id, type: 'contact', data: { id, name, emails: [f], keyFp: fp, encrypt: 'auto', sign: 'auto', notes: '', created: now(), updated: now() } }); }
      }
    }
    await ctx.save(changes);
    toast(keys.length === 1 ? 'Key imported.' : `${keys.length} keys imported.`);
    if (state.screen === 'keys') showKeys();
    return true;
  }

  $('#btnFindKey').addEventListener('click', () => lookupDialog(''));   // 1.4.0

  let ikBytes = null;   // a binary key file chosen in the import dialog
  $('#btnImportKey').addEventListener('click', async () => {
    ikBytes = null;
    const r = await dialog({
      title: 'Import keys',
      html: `<p class="muted small">Paste a public key (or your own secret key, still protected by its passphrase), or choose a .asc / .gpg file.</p>
        <textarea id="ikText" rows="10" spellcheck="false" placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----"></textarea>
        <div class="row-btns"><button class="btn small" id="ikFile" type="button">Choose file…</button><span id="ikName" class="muted small"></span></div>
        <p id="ikErr" class="error"></p>`,
      okText: 'Next', wide: true,
      onOk: async () => {
        const input = ikBytes || $('#ikText').value.trim();
        if (!input || !input.length) { $('#ikErr').textContent = 'Paste a key or choose a file.'; return false; }
        try { await keyring.read(input); } catch (e) { $('#ikErr').textContent = e.message; return false; }
        return input;
      }
    });
    if (r) { try { await importKeys(r); } catch (e) { toast(e.message, 'err'); } }
  });
  document.addEventListener('click', async e => {
    if (e.target.id !== 'ikFile') return;
    const [f] = await pickFiles({ multiple: false, accept: '.asc,.gpg,.pgp,.key,.txt' });
    if (!f) return;
    // keep the bytes on the dialog's text box
    const text = new TextDecoder().decode(f.bytes);
    if (text.includes('-----BEGIN PGP')) { $('#ikText').value = text; ikBytes = null; }
    else { $('#ikText').value = ''; $('#ikText').placeholder = '(binary key file loaded)'; ikBytes = f.bytes; }
    $('#ikName').textContent = f.filename;
  });

  /* =================================================================
   * 6. GENERATING A KEY PAIR
   * ================================================================= */
  $('#btnGenerateKey').addEventListener('click', async () => {
    const a = ctx.curAccount() || state.vault.accounts[0] || {};
    const r = await dialog({
      title: 'Generate key pair',
      html: `<label for="gName">Name</label><input type="text" id="gName" value="${esc(a.name || '')}">
        <label for="gEmail">Email</label><input type="text" id="gEmail" value="${esc(a.email || '')}">
        <div class="two-col"><div><label for="gAlg">Type</label><select id="gAlg"><option value="ecc">Modern (Ed25519 / Cv25519)</option><option value="rsa4096">RSA 4096 (older programs)</option></select></div>
        <div><label for="gExp">Expires after</label><select id="gExp"><option value="1">1 year</option><option value="2" selected>2 years</option><option value="5">5 years</option><option value="0">Never</option></select></div></div>
        <label for="gP1">Passphrase (at least 8 characters)</label><input type="password" id="gP1" autocomplete="new-password">
        <label for="gP2">Repeat passphrase</label><input type="password" id="gP2" autocomplete="new-password">
        <p class="muted small">The key is created in this browser and stored in your vault (still protected by this passphrase), so it is on all your devices. A revocation certificate is kept with it.</p>
        <p id="gErr" class="error"></p>`,
      okText: 'Generate',
      onOk: async () => {
        if ($('#gP1').value !== $('#gP2').value) { $('#gErr').textContent = 'Passphrases do not match'; return false; }
        $('#gErr').textContent = 'Generating…';
        try {
          const k = await keyring.generate({ name: $('#gName').value.trim(), email: $('#gEmail').value.trim(), passphrase: $('#gP1').value, algorithm: $('#gAlg').value, expireYears: $('#gExp').value });
          await ctx.save([{ id: 'key:' + k.fingerprint, type: 'key', data: k }]);
          return k.fingerprint;
        } catch (e) { $('#gErr').textContent = e.message; return false; }
      }
    });
    if (r) { selKey = r; toast('Key pair created and saved to your vault.'); showKeys(); }
  });

  /* =================================================================
   * 7. KEY UPKEEP (1.4.0) — the changed key syncs to all your devices
   * ================================================================= */
  async function extendDialog(k) {
    const fp = k.fingerprint;
    const ok = await dialog({
      title: 'Extend expiry',
      html: `<p>${esc(k.userIds[0] || '')} ${k.expires ? `expires <b>${esc(new Date(k.expires).toLocaleDateString())}</b>` : 'never expires'}. Extending keeps the same key and fingerprint — contacts only need your refreshed public key.</p>
        <label for="exYears">New expiry</label><select id="exYears"><option value="1">1 year from today</option><option value="2" selected>2 years from today</option><option value="5">5 years from today</option><option value="0">Never</option></select>
        <label for="exPass">Key passphrase</label><input type="password" id="exPass"><p id="exErr" class="error"></p>`,
      okText: 'Extend',
      onOk: async () => {
        $('#exErr').textContent = 'Working…';
        try {
          const data = await keyring.extendExpiry(fp, $('#exPass').value, $('#exYears').value, keyItem(fp) || {});
          await ctx.save([{ id: 'key:' + fp, type: 'key', data }]);
          return true;
        } catch (e) { $('#exErr').textContent = e.message; return false; }
      }
    });
    if (ok) { toast('Expiry extended. Send your updated public key to people who encrypt to you (or publish it).'); showKeys(); }
  }

  async function changePassDialog(k) {
    const fp = k.fingerprint;
    const ok = await dialog({
      title: 'Change key passphrase',
      html: `<label for="cpOld">Current passphrase</label><input type="password" id="cpOld">
        <label for="cpNew">New passphrase (at least 8 characters)</label><input type="password" id="cpNew" autocomplete="new-password">
        <label for="cpNew2">Repeat new passphrase</label><input type="password" id="cpNew2" autocomplete="new-password">
        <p class="muted small">The re-protected key syncs to all your devices.${k.remembered ? ' Because this key is remembered on all your devices, the new passphrase is saved there too.' : ''}</p>
        <p id="cpErr" class="error"></p>`,
      okText: 'Change passphrase',
      onOk: async () => {
        if ($('#cpNew').value !== $('#cpNew2').value) { $('#cpErr').textContent = 'New passphrases do not match'; return false; }
        $('#cpErr').textContent = 'Working…';
        try {
          const data = await keyring.changePassphrase(fp, $('#cpOld').value, $('#cpNew').value, keyItem(fp) || {});
          const changes = [{ id: 'key:' + fp, type: 'key', data }];
          if (state.vault.items.has('passphrase:' + fp)) changes.push({ id: 'passphrase:' + fp, type: 'passphrase', data: { fingerprint: fp, passphrase: $('#cpNew').value } });
          await ctx.save(changes);
          return true;
        } catch (e) { $('#cpErr').textContent = e.message; return false; }
      }
    });
    if (ok) { toast('Passphrase changed.'); showKeys(); }
  }

  async function revokeKey(k) {
    const fp = k.fingerprint;
    if (!(await confirmBox('Revoke key', 'Revoking is permanent. Use it if your key is lost or compromised, then share the updated public key (or publish it) so people stop using it.', 'Revoke key', true))) return;
    try {
      const data = await keyring.revoke(fp, (keyItem(fp) || {}).revocation, keyItem(fp) || {});
      await ctx.save([{ id: 'key:' + fp, type: 'key', data }]);
      toast('Key revoked.'); showKeys();
    } catch (e) { toast(e.message, 'err'); }
  }

  async function publishKey(k) {
    if (!(await confirmBox('Publish key', 'Upload your PUBLIC key to keys.openpgp.org so others can find it by email? The key server emails you a link to confirm each address.', 'Publish'))) return;
    try {
      const r = await ctx.vault.post('keys.php', 'publish', { armored: keyring.publicKeys.get(k.fingerprint).armor() });
      toast(r.verificationSentTo.length ? 'Uploaded. Check your inbox for the confirmation email from keys.openpgp.org.' : 'Uploaded.');
    } catch (e) { toast(e.message, 'err'); }
  }

  /* =================================================================
   * 8. FIND KEYS ONLINE (1.4.0)
   *    lookupDialog(email) — also used by the composer's "no key" chips.
   *    Resolves true when a key was imported.
   * ================================================================= */
  async function lookupDialog(email = '') {
    let results = [];
    const search = async () => {
      const asked = $('#luEmail').value.trim();
      const q = keyring.keyAddress(asked);   // 1.11.0: an addy.io address is searched as the real recipient inside it
      const note = q !== asked.toLowerCase() ? `<p class="muted small">addy.io address — searching for the real recipient, <b>${esc(q)}</b>.</p>` : '';
      $('#luOut').innerHTML = note + '<p class="muted small">Searching…</p>';
      try {
        const r = await ctx.vault.post('keys.php', 'lookup', { email: q });
        results = [];
        for (const f of r.found) {
          const bytes = f.format === 'binary' ? Uint8Array.from(atob(f.data), c => c.charCodeAt(0)) : f.data;
          try { for (const key of await keyring.read(bytes)) results.push({ source: f.source, key }); } catch { /* unreadable */ }
        }
        const seen = new Set();
        results = results.filter(x => { const fp = x.key.getFingerprint(); if (seen.has(fp)) return false; seen.add(fp); return true; });
        $('#luOut').innerHTML = note + (results.length ? results.map((x, i) => `
          <div class="lookup-result"><b>${esc(x.key.getUserIDs().join(', '))}</b> <span class="muted small">from ${esc(x.source)}</span>
            <div class="fp">${esc(x.key.getFingerprint().toUpperCase().replace(/(.{4})/g, '$1 '))}</div>
            <div class="small muted">Created ${esc(x.key.getCreationTime().toLocaleDateString())}${keyring.publicKeys.has(x.key.getFingerprint().toUpperCase()) ? ' · already in your keyring' : ''}</div>
            <button class="btn small primary" data-lu="${i}" type="button">Import</button></div>`).join('')
          : `<p class="muted">No key found for ${esc(q)}.${r.errors.length ? '<br>' + r.errors.map(esc).join('<br>') : ''}</p>`);
      } catch (e) { $('#luOut').innerHTML = `<p class="error">${esc(e.message)}</p>`; }
    };
    let imported = false;
    const p = dialog({
      title: 'Find a key online',
      html: `<p class="muted small">Looks in the person's own email domain (Web Key Directory) and on keys.openpgp.org.</p>
        <div class="row-btns" style="margin-top:0"><input type="text" id="luEmail" value="${esc(email)}" placeholder="name@example.com" style="flex:1"><button class="btn" id="luGo" type="button">Search</button></div>
        <div id="luOut"></div>`,
      okText: 'Close', hideCancel: true, wide: true
    });
    $('#luGo').onclick = search;
    $('#luEmail').onkeydown = e => { if (e.key === 'Enter') search(); };
    $('#luOut').onclick = async e => {
      const b = e.target.closest('[data-lu]');
      if (!b) return;
      const x = results[Number(b.dataset.lu)];
      const fp = x.key.getFingerprint().toUpperCase();
      try {
        const changes = [{ id: 'key:' + fp, type: 'key', data: await keyring.importData(x.key, keyItem(fp)) }];
        // the person becomes a contact with this key (or their contact gets it, if it had none)
        const em = ($('#luEmail').value || '').trim().toLowerCase();
        const kem = keyring.keyAddress(em);   // 1.11.0: or the contact of the real recipient inside an addy.io address
        const c = state.vault.contacts.find(y => (y.emails || []).includes(em)) || state.vault.contacts.find(y => (y.emails || []).includes(kem));
        if (c && !c.keyFp) changes.push({ id: 'contact:' + c.id, type: 'contact', data: { ...c, keyFp: fp, updated: now() } });
        await ctx.save(changes);
        imported = true;
        b.textContent = '✔ Imported'; b.disabled = true;
      } catch (err) { toast(err.message, 'err'); }
    };
    if (email) search();
    await p;
    if (imported && state.screen === 'keys') showKeys();
    return imported;
  }

  return { showContacts, showKeys, addContact, importKeys, lookupDialog };
}
