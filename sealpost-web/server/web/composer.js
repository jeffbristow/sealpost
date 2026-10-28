/* =====================================================================
 * Sealpost Web — composer.js  (writing mail)
 * ---------------------------------------------------------------------
 * Works like the composer in Sealpost on your PC: new / reply / reply
 * all / forward, plain or rich text, PGP sign / encrypt / hide subject /
 * attach my key, contact rules, recipient key status, attachments and
 * encrypted drafts that open in either one.
 *
 * Sections:
 *   1. Open / close / reset
 *   2. Rich text editor (toolbar, safe paste, plain <-> rich)
 *   3. Address autocomplete from Contacts
 *   4. Recipient key status + contact rules
 *   5. Attachments
 *   6. Drafts (encrypted, saved to the Drafts folder)
 *   7. Send
 * ===================================================================== */

import { $, $$, esc, escHtml, show, addr, fmtDate, fmtSize, toast, dialog, confirmBox, withPassphrase, pickFiles } from './ui.js?v=1.11.2';
import { composeMessage, buildDraft, parseAddressList, detectType, htmlToPlain } from './compose.js?v=1.11.2';
import { readDraft } from './reader.js?v=1.11.2';

const MAX_ATTACH = 25 * 1048576;

export function initComposer(ctx) {
  const { state, keyring, vault } = ctx;
  const c = {
    open: false, attachments: [], reply: null,
    draft: null,          // { accId, folder, uid } of the saved draft
    dirty: false, touched: {}, saving: false, sending: false
  };
  // 1.7.0: the From list holds "accId" or "accId|alias@address" ("Send as")
  const fromValue = () => { const v = $('#cFrom').value || ''; const i = v.indexOf('|'); return { accId: i < 0 ? v : v.slice(0, i), fromAddress: i < 0 ? null : v.slice(i + 1) }; };
  const acc = () => ctx.account(fromValue().accId);
  const fromEmail = () => fromValue().fromAddress || (acc() ? acc().email : '');
  /** Which of this account's "Send as" addresses a message was sent to (replies use it). */
  function aliasAddressedIn(view, a) {
    if (!a || !(a.aliases || []).length) return null;
    const got = [...(view.to || []), ...(view.cc || [])].map(x => (x.address || '').toLowerCase());
    if (got.includes(a.email.toLowerCase())) return null;
    const hit = a.aliases.find(x => got.includes(x.email.toLowerCase()));
    return hit ? hit.email : null;
  }

  /* =================================================================
   * 1. OPEN / CLOSE / RESET
   * ================================================================= */
  async function openComposer({ mode = 'new', view = null, to = '', draft = null } = {}) {
    if (!state.vault || !state.vault.accounts.length) { toast('Add an email account in Sealpost on your PC first.', 'err'); return; }
    if (c.open && !(await closeComposer())) return;
    Object.assign(c, { open: true, attachments: [], reply: null, draft: null, dirty: false, touched: {} });

    const from = $('#cFrom');
    from.innerHTML = state.vault.accounts.map(a =>
      `<option value="${esc(a.id)}">${esc(a.name ? `${a.name} <${a.email}>` : a.email)}</option>` +
      (a.aliases || []).map(x => `<option value="${esc(a.id + '|' + x.email)}">${esc(`${x.name || a.name ? (x.name || a.name) + ' ' : ''}<${x.email}>  · send as`)}</option>`).join('')
    ).join('');
    const baseAcc = (draft && draft.accId) || (view && view.accId) || (state.cur.accId !== '__all__' && state.cur.accId) || state.vault.accounts[0].id;   // 1.8.0: not "All Inboxes"
    from.value = baseAcc;
    // 1.7.0: a draft keeps its "Send as" address; a reply uses the address the message came to
    const wantAlias = draft ? draft.meta && draft.meta.fromAddress : view ? aliasAddressedIn(view, ctx.account(baseAcc)) : null;
    if (wantAlias && [...from.options].some(o => o.value === baseAcc + '|' + wantAlias)) from.value = baseAcc + '|' + wantAlias;
    const a = acc();
    const s = state.vault.settings;

    const rich = draft ? (draft.meta && draft.meta.format === 'rich') : s.composeFormat === 'rich';
    let subject = '', toList = to, ccList = '', bccList = '', text = '', html = '';
    const sigText = a && a.signature ? '\n\n-- \n' + a.signature : '';
    const sigHtml = a && a.signature ? '<br><br>-- <br>' + escHtml(a.signature) : '';

    if (draft) {
      toList = draft.to; ccList = draft.cc; bccList = draft.bcc; subject = draft.subject;
      text = draft.text || ''; html = draft.html || '';
      c.draft = { accId: draft.accId, folder: draft.folder, uid: draft.uid };
      c.attachments = draft.attachments || [];
      const m = draft.meta || {};
      if (m.inReplyTo) c.reply = { inReplyTo: m.inReplyTo, references: m.references, uid: m.replyToUid, folder: m.replyFolder };
    } else if (view) {
      const header = (view.date ? `On ${fmtDate(view.date, true)}, ` : '') + `${addr(view.from[0])} wrote:`;
      const original = (view.text || '').replace(/\r\n?/g, '\n').trimEnd();
      if (mode === 'forward') {
        subject = /^fwd?:/i.test(view.subject) ? view.subject : 'Fwd: ' + view.subject;
        const fwdHead = `---------- Forwarded message ----------\nFrom: ${view.from.map(addr).join(', ')}\nDate: ${fmtDate(view.date, true)}\nSubject: ${view.subject}\nTo: ${view.to.map(addr).join(', ')}`;
        text = `${sigText}\n\n${fwdHead}\n\n${original}`;
        html = `<p><br></p>${sigHtml}<p><br></p><div>${escHtml(fwdHead)}<br><br>${escHtml(original)}</div>`;
        // the original's attachments go along
        c.attachments = view.attachments.filter(x => !x.inline).map(x => ({ filename: x.filename, contentType: x.contentType, bytes: x.bytes }));
      } else {
        subject = /^re:/i.test(view.subject) ? view.subject : 'Re: ' + view.subject;
        const replyTo = view.replyTo.length ? view.replyTo : view.from;
        toList = replyTo.map(addr).join(', ');
        if (mode === 'replyAll') {
          const me = state.vault.accounts.flatMap(x => [x.email, ...(x.aliases || []).map(y => y.email)]).map(e => e.toLowerCase());   // 1.7.0
          const others = [...view.to, ...view.cc].filter(x => !me.includes((x.address || '').toLowerCase()) && !replyTo.some(r => r.address === x.address));
          ccList = others.map(addr).join(', ');
        }
        text = `${sigText}\n\n${header}\n${original.split('\n').map(l => '> ' + l).join('\n')}`;
        html = `<p><br></p>${sigHtml}<p><br></p><div>${esc(header)}</div><blockquote>${escHtml(original)}</blockquote>`;
        c.reply = { inReplyTo: view.messageId, references: [view.references, view.messageId].filter(Boolean).join(' '), uid: view.uid, folder: view.folder };
      }
    } else {
      text = sigText;
      html = sigHtml ? `<p><br></p>${sigHtml}` : '<p><br></p>';
    }

    $('#composeTitle').textContent = draft ? 'Draft' : { new: 'New message', reply: 'Reply', replyAll: 'Reply all', forward: 'Forward' }[mode];
    $('#cTo').value = toList || '';
    $('#cCc').value = ccList || '';
    $('#cBcc').value = bccList || '';
    show($('#cCcRow'), !!ccList || !!bccList); show($('#cBccRow'), !!bccList);
    show($('#cShowCc'), !ccList && !bccList);
    $('#cSubject').value = subject || '';
    setRich(rich, { text, html: html || escHtml(text) });

    const m = draft && draft.meta;
    $('#cSign').checked = m ? !!m.sign : !!s.defaultSign;
    $('#cEncrypt').checked = m ? !!m.encrypt : (!!(view && view.pgp && view.pgp.encrypted) || !!s.defaultEncrypt);
    $('#cHideSubject').checked = m ? !!m.hideSubject : false;
    $('#cAttachKey').checked = m ? !!m.attachPublicKey : !!s.attachPublicKey;
    if (m) c.touched = { encrypt: true, sign: true };
    $('#cDraftStatus').textContent = draft ? (draft.encrypted ? '🔒 Encrypted draft' : 'Draft') : '';
    renderAttachments();
    show($('#composeModal'), true);
    document.body.classList.add('composing');
    await updateKeyStatus(true);
    setTimeout(() => {
      if (!$('#cTo').value) $('#cTo').focus();
      else if (isRich()) { $('#cEditor').focus(); caretToStart($('#cEditor')); }
      else { $('#cBody').focus(); $('#cBody').setSelectionRange(0, 0); }
    }, 50);
  }

  /** Close: offer to save a draft. Resolves true when closed. */
  async function closeComposer() {
    hideAc();
    const empty = !recipients().length && !$('#cSubject').value.trim() && !bodyPlain().trim() && !c.attachments.length;
    if ((empty && !c.draft) || (!c.dirty && c.draft)) { finishClose(); return true; }
    const choice = await dialog({
      title: 'Close message',
      html: '<p>Save this message as a draft so you can finish it later — here or in Sealpost on your PC?</p><p class="muted small">Drafts are encrypted to your own key in this browser before they are stored on your mail server.</p>',
      okText: 'Save draft', cancelText: 'Keep writing', extraText: 'Discard'
    });
    if (choice === 'extra') { await discard(true); return true; }
    if (!choice) return false;
    clearTimeout(draftTimer);
    if (!(await saveDraftNow(true))) return false;
    finishClose();
    return true;
  }

  function finishClose() {
    clearTimeout(draftTimer);
    c.open = false;
    show($('#composeModal'), false);
    document.body.classList.remove('composing');
  }

  async function discard(confirmed = false) {
    if (!confirmed && !(await confirmBox('Discard message', 'Delete this message' + (c.draft ? ' and its saved draft' : '') + '?', 'Discard', true))) return;
    clearTimeout(draftTimer);
    if (c.draft) {
      try { await vault.mail('deleteDraft', { account: vault.imapDetails(ctx.account(c.draft.accId)), folder: c.draft.folder, uid: c.draft.uid }); } catch { /* ignore */ }
      refreshIfDrafts();
    }
    c.draft = null; c.dirty = false;
    finishClose();
  }

  $('#cClose').addEventListener('click', closeComposer);
  $('#cDiscard').addEventListener('click', () => discard());
  $('#cShowCc').addEventListener('click', () => { show($('#cCcRow'), true); show($('#cBccRow'), true); show($('#cShowCc'), false); $('#cCc').focus(); });

  /* =================================================================
   * 2. RICH TEXT EDITOR
   * ================================================================= */
  const isRich = () => $('#cRich').checked;

  function setRich(on, { text, html } = {}) {
    $('#cRich').checked = on;
    $('#cToolbar').classList.toggle('plain', !on);
    show($('#cEditor'), on);
    show($('#cBody'), !on);
    if (on) $('#cEditor').innerHTML = sanitizeHtml(html != null ? html : escHtml(text || ''));
    else $('#cBody').value = text != null ? text : '';
  }

  const bodyPlain = () => isRich() ? $('#cEditor').innerText : $('#cBody').value;

  $('#cRich').addEventListener('change', async () => {
    if (isRich()) setRich(true, { html: escHtml($('#cBody').value) });
    else {
      const hasFormatting = /<(b|strong|i|em|u|s|ul|ol|font|span|a|blockquote|h\d)\b/i.test($('#cEditor').innerHTML);
      if (hasFormatting && !(await confirmBox('Switch to plain text', 'Formatting (bold, lists, links) will be removed. Continue?', 'Switch'))) { $('#cRich').checked = true; return; }
      setRich(false, { text: $('#cEditor').innerText.replace(/\n{3,}/g, '\n\n') });
    }
    markDirty();
  });

  function caretToStart(el) {
    const r = document.createRange(); r.setStart(el, 0); r.collapse(true);
    const sel = window.getSelection(); sel.removeAllRanges(); sel.addRange(r);
  }

  $$('#cToolbar [data-cmd]').forEach(b => b.addEventListener('mousedown', e => {
    e.preventDefault(); // keep the selection in the editor
    const cmd = b.dataset.cmd;
    $('#cEditor').focus();
    if (cmd === 'quote') document.execCommand('formatBlock', false, 'blockquote');
    else if (cmd === 'link') {
      const sel = window.getSelection();
      const range = sel.rangeCount ? sel.getRangeAt(0).cloneRange() : null;
      dialog({
        title: 'Insert link', okText: 'Insert',
        html: '<label>Web address</label><input type="text" id="lnkUrl" placeholder="https://"><p id="lnkErr" class="error"></p>',
        onOk: () => {
          let url = $('#lnkUrl').value.trim();
          if (!/^(https?:|mailto:)/i.test(url)) url = 'https://' + url;
          if (!/^(https?:\/\/[^\s]+|mailto:[^\s]+)$/i.test(url)) { $('#lnkErr').textContent = 'Enter a web or mailto: address'; return false; }
          $('#cEditor').focus();
          if (range) { sel.removeAllRanges(); sel.addRange(range); }
          if (range && !range.collapsed) document.execCommand('createLink', false, url);
          else document.execCommand('insertHTML', false, `<a href="${esc(url)}">${esc(url)}</a>`);
          markDirty();
          return true;
        }
      });
      return;
    } else document.execCommand(cmd, false, null);
    toolbarState();
    markDirty();
  }));

  function toolbarState() {
    for (const cmd of ['bold', 'italic', 'underline', 'strikeThrough', 'insertUnorderedList', 'insertOrderedList']) {
      const b = $(`#cToolbar [data-cmd="${cmd}"]`);
      try { b.classList.toggle('on', document.queryCommandState(cmd)); } catch { /* ignore */ }
    }
  }
  document.addEventListener('selectionchange', () => { if (document.activeElement === $('#cEditor')) toolbarState(); });

  // pasted HTML is cleaned: no scripts, no remote images, only basic formatting
  const ALLOWED_TAGS = new Set(['B', 'STRONG', 'I', 'EM', 'U', 'S', 'STRIKE', 'P', 'DIV', 'BR', 'UL', 'OL', 'LI', 'BLOCKQUOTE', 'A', 'SPAN', 'FONT', 'H1', 'H2', 'H3', 'H4', 'PRE', 'CODE', 'TABLE', 'THEAD', 'TBODY', 'TR', 'TD', 'TH', 'SUB', 'SUP', 'HR']);
  const ALLOWED_STYLES = ['color', 'background-color', 'font-weight', 'font-style', 'text-decoration', 'font-size', 'text-align'];
  function sanitizeHtml(html) {
    const doc = new DOMParser().parseFromString(`<div>${html || ''}</div>`, 'text/html');
    const root = doc.body.firstChild;
    (function clean(node) {
      for (const child of [...node.childNodes]) {
        if (child.nodeType === 3) continue;
        if (child.nodeType !== 1) { child.remove(); continue; }
        if (!ALLOWED_TAGS.has(child.tagName)) {
          if (['SCRIPT', 'STYLE', 'IFRAME', 'OBJECT', 'EMBED', 'IMG', 'SVG', 'VIDEO', 'AUDIO', 'TITLE', 'META', 'LINK', 'HEAD', 'FORM', 'INPUT', 'BUTTON'].includes(child.tagName)) { child.remove(); continue; }
          clean(child);
          child.replaceWith(...child.childNodes);
          continue;
        }
        for (const attr of [...child.attributes]) {
          const n = attr.name.toLowerCase();
          if (n === 'href' && child.tagName === 'A' && /^(https?:|mailto:)/i.test(attr.value.trim())) continue;
          if (n === 'style') {
            const kept = ALLOWED_STYLES.map(p => child.style.getPropertyValue(p) ? `${p}: ${child.style.getPropertyValue(p)}` : '').filter(Boolean).join('; ');
            if (kept) { child.setAttribute('style', kept); continue; }
          }
          if (child.tagName === 'FONT' && (n === 'color' || n === 'size')) continue;
          if (['colspan', 'rowspan'].includes(n)) continue;
          child.removeAttribute(attr.name);
        }
        clean(child);
      }
    })(root);
    return root.innerHTML;
  }

  $('#cEditor').addEventListener('paste', e => {
    const html = e.clipboardData.getData('text/html');
    const text = e.clipboardData.getData('text/plain');
    e.preventDefault();
    document.execCommand('insertHTML', false, html ? sanitizeHtml(html) : escHtml(text));
    markDirty();
  });
  $('#cEditor').addEventListener('drop', e => e.preventDefault());
  $('#cEditor').addEventListener('input', markDirty);
  $('#cEditor').addEventListener('click', e => { if (e.target.closest('a')) e.preventDefault(); });
  $('#cBody').addEventListener('input', markDirty);
  $('#cSubject').addEventListener('input', markDirty);

  /* =================================================================
   * 3. ADDRESS AUTOCOMPLETE — from Contacts (and keys in your keyring)
   * ================================================================= */
  let acField = null, acItems = [], acSel = 0, acTimer;
  function token(input) {
    const v = input.value, pos = input.selectionStart;
    const start = v.lastIndexOf(',', pos - 1) + 1;
    return { start, end: pos, text: v.slice(start, pos).trim() };
  }
  function hideAc() { show($('#acBox'), false); acField = null; acItems = []; }
  function suggestions(q) {
    q = q.toLowerCase();
    const out = [], seen = new Set(recipients());
    for (const ct of [...state.vault.contacts].sort((x, y) => (x.name || '').localeCompare(y.name || ''))) {
      for (const e of ct.emails || []) {
        if (seen.has(e) || !((ct.name || '').toLowerCase().includes(q) || e.includes(q))) continue;
        seen.add(e); out.push({ name: ct.name, email: e, hasKey: !!ct.keyFp || !!keyring.pinned(e) });
      }
    }
    for (const [, k] of keyring.publicKeys) {
      for (const u of k.getUserIDs()) {
        const m = u.match(/^(.*?)\s*<([^>]+)>/); const e = (m ? m[2] : u).toLowerCase(); const n = m ? m[1].replace(/"/g, '').trim() : '';
        if (!e.includes('@') || seen.has(e) || !(n.toLowerCase().includes(q) || e.includes(q))) continue;
        seen.add(e); out.push({ name: n, email: e, hasKey: true });
      }
    }
    return out.slice(0, 8);
  }
  function showAc(input) {
    const t = token(input);
    if (t.text.length < 1 || t.text.includes('<')) return hideAc();
    const res = suggestions(t.text);
    if (!res.length) return hideAc();
    acField = input; acItems = res; acSel = 0;
    const box = $('#acBox');
    box.innerHTML = '';
    res.forEach((r, i) => {
      const el = document.createElement('div');
      el.className = 'ac-item' + (i === 0 ? ' sel' : '');
      el.innerHTML = `<span class="ac-lock" title="${r.hasKey ? 'Has a PGP key' : 'No key'}">${r.hasKey ? '🔒' : ''}</span><span>${esc(r.name || r.email)}</span>${r.name ? `<span class="ac-email">${esc(r.email)}</span>` : ''}`;
      el.onmousedown = e => { e.preventDefault(); pickAc(i); };
      box.appendChild(el);
    });
    const rect = input.getBoundingClientRect();
    Object.assign(box.style, { left: rect.left + 'px', top: rect.bottom + 2 + 'px', width: rect.width + 'px' });
    show(box, true);
  }
  function pickAc(i) {
    const r = acItems[i], input = acField;
    if (!r || !input) return;
    const t = token(input);
    const entry = r.name ? `${r.name.replace(/[",<>]/g, '')} <${r.email}>` : r.email;
    const before = input.value.slice(0, t.start).trim();
    const after = input.value.slice(t.end).replace(/^[^,]*/, '');
    input.value = (before ? before + ' ' : '') + entry + ', ' + after.replace(/^,\s*/, '');
    hideAc(); input.focus(); markDirty(); updateKeyStatus();
  }
  $$('.addr-input').forEach(input => {
    input.addEventListener('input', () => { clearTimeout(acTimer); acTimer = setTimeout(() => showAc(input), 100); markDirty(); clearTimeout(keyTimer); keyTimer = setTimeout(updateKeyStatus, 500); });
    input.addEventListener('keydown', e => {
      if ($('#acBox').classList.contains('hidden') || acField !== input) return;
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault();
        acSel = (acSel + (e.key === 'ArrowDown' ? 1 : -1) + acItems.length) % acItems.length;
        $$('.ac-item').forEach((el, i) => el.classList.toggle('sel', i === acSel));
      } else if (e.key === 'Enter' || e.key === 'Tab') { e.preventDefault(); pickAc(acSel); }
      else if (e.key === 'Escape') { e.stopPropagation(); hideAc(); }
    });
    input.addEventListener('blur', () => setTimeout(() => { if (acField === input) hideAc(); }, 150));
  });

  /* =================================================================
   * 4. RECIPIENT KEY STATUS + CONTACT RULES
   * ================================================================= */
  const recipients = () => ['#cTo', '#cCc', '#cBcc'].flatMap(id => parseAddressList($(id).value)).map(a => a.address.toLowerCase());
  let keyTimer;
  async function updateKeyStatus(initial = false) {
    const emails = [...new Set(recipients())];
    const box = $('#cKeyStatus');
    const a = acc();
    const fe = fromEmail(), alias = !!fromValue().fromAddress;
    const mine = a ? await keyring.findSecretFor(fe) : null;
    const fallback = !mine && alias && a ? await keyring.findSecretFor(a.email) : null;   // 1.7.0: alias signs with the account key
    box.innerHTML = '';
    if (!mine) {
      const chip = document.createElement('span');
      chip.className = 'key-chip ' + (fallback ? 'info' : 'missing');
      chip.textContent = fallback ? `Signing as ${fe} with your ${a.email} key` : `No private key for ${fe} — create one under Keys`;
      chip.onclick = () => { closeComposer().then(ok => { if (ok) ctx.switchView('keys'); }); };
      box.appendChild(chip);
    }
    if (!emails.length) { $('#cHint').textContent = ''; return; }
    const st = await keyring.recipientStatus(emails);
    let allOk = true, wantEncrypt = false, signRule = null, viaAddy = false;
    for (const e of emails) {
      const s = st[e] || {};
      // 1.11.0: an addy.io address is shown as the real recipient its key belongs to
      if (s.keyAddress) viaAddy = true;
      const ct = state.vault.contacts.find(x => (x.emails || []).includes(e)) || (s.keyAddress ? state.vault.contacts.find(x => (x.emails || []).includes(s.keyAddress)) : null);
      const who = (ct && ct.name ? ct.name : s.keyAddress || e) + (s.keyAddress ? ' (via addy.io)' : '');
      const chip = document.createElement('span');
      if (s.ok) {
        chip.className = 'key-chip ok';
        chip.innerHTML = `🔑 ${esc(who)}${s.verified ? ' <span title="Fingerprint verified">✔</span>' : ''}`;
        chip.title = `${e}${s.keyAddress ? `\nThrough addy.io to ${s.keyAddress} — encrypted to their key` : ''}\nKey ${s.fingerprint}${s.pinned ? '\n(assigned in Contacts)' : ''}`;
      } else {
        allOk = false;
        chip.className = 'key-chip missing';
        const why = { expired: 'key expired', revoked: 'key revoked', missing: 'assigned key missing', unusable: 'key unusable' }[s.problem] || 'no key';
        chip.textContent = `⚠ ${why}: ${who}`;
        chip.title = 'Click to look for this person\'s key online';
        chip.onclick = async () => { if (await ctx.lookupKey(e)) updateKeyStatus(); };   // 1.4.0
      }
      box.appendChild(chip);
      if (s.otherKey) {
        const w = document.createElement('span');
        w.className = 'key-chip changed';
        w.textContent = `⚠ ${who}: another key exists`;
        w.title = 'A different key for this address is in your keyring. The key assigned in Contacts is still used.';
        box.appendChild(w);
      }
      if (ct) {
        if (ct.encrypt === 'always') wantEncrypt = true;
        if (ct.sign === 'never') signRule = 'never';
        else if (ct.sign === 'always' && signRule !== 'never') signRule = 'always';
      }
    }
    if (!c.touched.encrypt) {
      if (wantEncrypt) $('#cEncrypt').checked = true;
      else if (initial && state.vault.settings.defaultEncrypt) $('#cEncrypt').checked = allOk;
    }
    if (!c.touched.sign && signRule) $('#cSign').checked = signRule === 'always';
    $('#cHint').textContent = [
      $('#cEncrypt').checked && !allOk ? 'Some recipients have no usable key — encryption will fail.' : '',
      // 1.11.0: addy.io hides your address, but the message itself can still name your key
      viaAddy && ($('#cSign').checked || $('#cAttachKey').checked) ? 'Through addy.io they see your alias, but a signature or attached key shows the addresses on your key.' : ''
    ].filter(Boolean).join(' ');
  }
  $('#cFrom').addEventListener('change', () => { updateKeyStatus(); markDirty(); });
  $('#cEncrypt').addEventListener('change', () => { c.touched.encrypt = true; updateKeyStatus(); markDirty(); });
  $('#cSign').addEventListener('change', () => { c.touched.sign = true; markDirty(); updateKeyStatus(); });
  ['#cHideSubject', '#cAttachKey'].forEach(id => $(id).addEventListener('change', markDirty));
  $('#cAttachKey').addEventListener('change', () => updateKeyStatus());   // 1.11.0: addy.io hint

  /* =================================================================
   * 5. ATTACHMENTS — read in the browser; encrypted with the message
   * ================================================================= */
  function renderAttachments() {
    const box = $('#cAttachments');
    box.innerHTML = '';
    c.attachments.forEach((a, i) => {
      const chip = document.createElement('span');
      chip.className = 'chip';
      chip.innerHTML = `📎 ${esc(a.filename)} <span class="muted">${fmtSize(a.bytes.length)}</span>`;
      const x = document.createElement('button'); x.type = 'button'; x.textContent = '✕'; x.title = 'Remove';
      x.onclick = () => { c.attachments.splice(i, 1); renderAttachments(); markDirty(); };
      chip.appendChild(x);
      box.appendChild(chip);
    });
  }
  $('#cAttach').addEventListener('click', async () => {
    const files = await pickFiles();
    const total = c.attachments.reduce((n, a) => n + a.bytes.length, 0) + files.reduce((n, a) => n + a.bytes.length, 0);
    if (total > MAX_ATTACH) { toast('Attachments are limited to 25 MB per message.', 'err'); return; }
    c.attachments.push(...files.map(f => ({ ...f, contentType: f.contentType || detectType(f.filename) })));
    renderAttachments();
    if (files.length) markDirty();
  });

  function payload() {
    const rich = isRich();
    return {
      to: $('#cTo').value, cc: $('#cCc').value, bcc: $('#cBcc').value,
      subject: $('#cSubject').value,
      text: rich ? '' : $('#cBody').value,
      html: rich ? sanitizeHtml($('#cEditor').innerHTML) : null,
      encrypt: $('#cEncrypt').checked, sign: $('#cSign').checked,
      hideSubject: $('#cHideSubject').checked && $('#cEncrypt').checked,
      attachPublicKey: $('#cAttachKey').checked,
      attachments: c.attachments,
      inReplyTo: c.reply && c.reply.inReplyTo, references: c.reply && c.reply.references,
      replyToUid: c.reply && c.reply.uid, replyFolder: c.reply && c.reply.folder,
      fromAddress: fromValue().fromAddress          // 1.7.0: "Send as" (null = the account's own address)
    };
  }

  /* =================================================================
   * 6. DRAFTS — saved a few seconds after you stop typing
   * ================================================================= */
  let draftTimer;
  function markDirty() {
    if (!c.open) return;
    c.dirty = true;
    clearTimeout(draftTimer);
    draftTimer = setTimeout(() => saveDraftNow(), 8000);
  }

  /** Post a finished message (bytes) with its details to mail.php. */
  async function postRaw(action, raw, meta) {
    const res = await fetch('mail.php?action=' + action, {
      method: 'POST', credentials: 'omit', cache: 'no-store',
      headers: { 'Content-Type': 'application/octet-stream', 'X-Sealpost-Token': vault.token() || '', 'X-Sealpost-Meta': btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(meta)))) },
      body: new TextEncoder().encode(raw)
    });
    let json;
    try { json = await res.json(); } catch { throw new Error('The server sent an unexpected reply (HTTP ' + res.status + ').'); }
    if (!json.ok) throw Object.assign(new Error(json.message || json.error), { code: json.error });
    return json;
  }

  async function saveDraftNow(final = false) {
    if (c.saving) { if (!final) return true; await new Promise(r => setTimeout(r, 600)); }
    if (c.sending) return true;
    const a = acc();
    if (!a) return false;
    c.saving = true; c.dirty = false;
    $('#cDraftStatus').textContent = 'Saving draft…';
    try {
      let prev = c.draft;
      if (prev && prev.accId !== a.id) {   // From changed: the old account's draft goes
        try { await vault.mail('deleteDraft', { account: vault.imapDetails(ctx.account(prev.accId)), folder: prev.folder, uid: prev.uid }); } catch { /* ignore */ }
        prev = null;
      }
      const built = await buildDraft(keyring, a, payload());
      const r = await postRaw('saveDraft', built.raw, { imap: vault.imapDetails(a), messageId: built.messageId, replace: prev ? { folder: prev.folder, uid: prev.uid } : null });
      c.draft = r.uid ? { accId: a.id, folder: r.folder, uid: r.uid } : null;
      $('#cDraftStatus').textContent = (built.encrypted ? '🔒 Encrypted draft saved ' : 'Draft saved (not encrypted — no key of your own) ') + new Date().toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
      refreshIfDrafts();
      return true;
    } catch (e) {
      c.dirty = true;
      $('#cDraftStatus').textContent = 'Draft not saved: ' + e.message;
      if (final) toast('Draft not saved: ' + e.message, 'err');
      return false;
    } finally { c.saving = false; }
  }
  $('#cSaveDraft').addEventListener('click', () => { clearTimeout(draftTimer); saveDraftNow(true); });

  function refreshIfDrafts() { if (ctx.isDraftsFolder()) ctx.loadMessages({ quiet: true }); }

  /** Clicking a message in the Drafts folder reopens it here. */
  async function openDraft(uid) {
    try {
      const a = ctx.curAccount();
      const r = await ctx.mailCall('message', { folder: state.cur.folder, uid }, { raw: true });
      const d = await withPassphrase(keyring, () => readDraft(r.bytes, keyring));
      await openComposer({ draft: { ...d, accId: a.id, folder: state.cur.folder, uid } });
    } catch (e) { if (e.code !== 'CANCELLED') toast('Could not open draft: ' + e.message, 'err'); }
  }

  /* =================================================================
   * 7. SEND
   * ================================================================= */
  $('#cSend').addEventListener('click', send);
  async function send() {
    hideAc();
    const a = acc();
    const d = payload();
    if (!recipients().length) return toast('Add at least one recipient', 'err');
    if (!d.subject && !(await confirmBox('No subject', 'Send without a subject?', 'Send'))) return;
    if (!bodyPlain().trim() && !c.attachments.length && !(await confirmBox('Empty message', 'Send a message with no text?', 'Send'))) return;
    clearTimeout(draftTimer);
    const btn = $('#cSend');
    btn.disabled = true; c.sending = true;
    try {
      btn.textContent = d.encrypt ? 'Encrypting…' : d.sign ? 'Signing…' : 'Sending…';
      const built = await withPassphrase(keyring, () => composeMessage(keyring, a, d));
      btn.textContent = 'Sending…';
      const draftRef = c.draft && c.draft.accId === a.id ? { folder: c.draft.folder, uid: c.draft.uid } : null;
      const r = await postRaw('send', built.raw, {
        smtp: smtpDetails(a), imap: vault.imapDetails(a),
        from: built.envelope.from, to: built.envelope.to,   // 1.7.0: the "Send as" address when chosen
        replied: c.reply && c.reply.uid && c.reply.folder ? { folder: c.reply.folder, uid: c.reply.uid } : null,
        draft: draftRef
      });
      if (c.draft && c.draft.accId !== a.id) { try { await vault.mail('deleteDraft', { account: vault.imapDetails(ctx.account(c.draft.accId)), folder: c.draft.folder, uid: c.draft.uid }); } catch { /* ignore */ } }
      c.draft = null; c.dirty = false;
      finishClose();
      toast(d.encrypt ? '🔒 Encrypted message sent' : d.sign ? '✍ Signed message sent' : 'Message sent');
      for (const w of r.warnings || []) toast(w, 'err');
      if (c.reply && a.id === state.cur.accId) { const m = state.messages.find(x => x.uid === c.reply.uid); if (m) { m.answered = true; ctx.renderList(); } }
      refreshIfDrafts();
      autoAddContacts(d);
    } catch (e) {
      if (e.code === 'MISSING_KEYS') { toast('Missing public keys for: ' + e.missing.join(', ') + '. Import their keys under Keys, or turn off Encrypt.', 'err'); updateKeyStatus(); }
      else if (e.code !== 'CANCELLED') toast('Send failed: ' + e.message, 'err');
      markDirty();
    } finally {
      btn.disabled = false; btn.textContent = 'Send'; c.sending = false;
    }
  }

  function smtpDetails(a) {
    return {
      host: a.smtpHost, port: a.smtpPort, security: a.smtpSecurity,
      username: a.smtpUsername || a.username || a.email, password: a.smtpPassword || a.password, allowSelfSigned: !!a.allowSelfSigned
    };
  }

  /** "Add people I write to as contacts automatically" (your Sealpost setting). */
  async function autoAddContacts(d) {
    if (state.vault.settings.autoAddContacts === false) return;
    const known = new Set(state.vault.contacts.flatMap(x => x.emails || []));
    const mine = new Set(state.vault.accounts.flatMap(x => [x.email, ...(x.aliases || []).map(y => y.email)]).map(e => e.toLowerCase()));
    const add = [];
    for (const p of [...parseAddressList(d.to), ...parseAddressList(d.cc), ...parseAddressList(d.bcc)]) {
      const e = p.address.toLowerCase();
      if (known.has(e) || mine.has(e)) continue;
      known.add(e);
      const now = new Date().toISOString();
      const id = crypto.randomUUID();
      add.push({ id: 'contact:' + id, type: 'contact', data: { id, name: p.name || '', emails: [e], keyFp: null, encrypt: 'auto', sign: 'auto', notes: '', created: now, updated: now } });
    }
    if (add.length) { try { await ctx.save(add); } catch { /* not important */ } }
  }

  /* ---------- keyboard: Ctrl+Enter sends, Esc closes ---------- */
  $('#composeModal').addEventListener('keydown', e => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); send(); }
    if (e.key === 'Escape' && $('#acBox').classList.contains('hidden') && $('#dlgModal').classList.contains('hidden')) { e.preventDefault(); closeComposer(); }
  });

  return {
    openComposer, openDraft,
    isOpen: () => c.open,
    isDirty: () => c.dirty,
    reset: () => { clearTimeout(draftTimer); c.open = false; show($('#composeModal'), false); document.body.classList.remove('composing'); }
  };
}
