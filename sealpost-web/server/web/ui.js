/* =====================================================================
 * Sealpost Web — ui.js
 * ---------------------------------------------------------------------
 * Small building blocks shared by every screen.
 *
 * Sections:
 *   1. DOM + text helpers (escaping, dates, sizes)
 *   2. Toasts, loading screen, downloads, clipboard
 *   3. Dialogs (generic, confirm, choose-one-of-three)
 *   4. Key passphrase prompt + "retry after unlocking"
 * ===================================================================== */

/* =================================================================
 * 1. DOM + TEXT HELPERS
 * ================================================================= */
export const $ = sel => document.querySelector(sel);
export const $$ = sel => [...document.querySelectorAll(sel)];
export const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export const escHtml = s => esc(s).replace(/\n/g, '<br>');
export const show = (el, on = true) => el && el.classList.toggle('hidden', !on);
export const addr = a => a ? (a.name ? `${a.name} <${a.address}>` : a.address) : '';
export const addrShort = a => a ? (a.name || a.address) : '';

export function fmtDate(iso, long = false) {
  if (!iso) return '';
  const d = new Date(iso), now = new Date();
  if (long) return d.toLocaleString(undefined, { dateStyle: 'full', timeStyle: 'short' });
  if (d.toDateString() === now.toDateString()) return d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
  if (d.getFullYear() === now.getFullYear()) return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  return d.toLocaleDateString();
}

export function fmtSize(n) {
  if (n == null) return '';
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(0) + ' KB';
  return (n / 1048576).toFixed(1) + ' MB';
}

/* =================================================================
 * 2. TOASTS, LOADING, DOWNLOADS, CLIPBOARD
 * ================================================================= */
export function toast(msg, kind = '') {
  const t = document.createElement('div');
  t.className = 'toast ' + kind;
  t.textContent = msg;
  $('#toasts').appendChild(t);
  setTimeout(() => t.remove(), kind === 'err' ? 9000 : 4500);
}

export function loading(text) {
  if (text) $('#loadingText').textContent = text;
  show($('#loading'), !!text);
}

/** Hand the browser a file to save (stays on this device — nothing is uploaded). */
export function download(bytes, filename, type = 'application/octet-stream') {
  const url = URL.createObjectURL(new Blob([bytes], { type }));
  const a = document.createElement('a');
  a.href = url; a.download = filename || 'download';
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
}

export async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; }
  catch {
    const t = document.createElement('textarea');
    t.value = text; document.body.appendChild(t); t.select();
    const ok = document.execCommand('copy'); t.remove();
    return ok;
  }
}

/** Ask the browser for files; resolves [{ filename, contentType, bytes }]. */
export function pickFiles({ multiple = true, accept = '' } = {}) {
  return new Promise(resolve => {
    const input = document.createElement('input');
    input.type = 'file'; input.multiple = multiple; if (accept) input.accept = accept;
    input.onchange = async () => {
      const out = [];
      for (const f of input.files) out.push({ filename: f.name, contentType: f.type || '', bytes: new Uint8Array(await f.arrayBuffer()) });
      resolve(out);
    };
    input.click();
  });
}

/* =================================================================
 * 3. DIALOGS
 *    dialog({ title, html, okText, cancelText, hideCancel, onOk,
 *             danger, extraText, wide })
 *    resolves: value from onOk (or true) | null (cancel) | 'extra'
 * ================================================================= */
export function dialog({ title, html, okText = 'OK', cancelText = 'Cancel', hideCancel = false, onOk, danger = false, extraText = null, wide = false }) {
  return new Promise(resolve => {
    $('#dlgTitle').textContent = title;
    $('#dlgBody').innerHTML = html;
    $('#dlgModal .modal-card').classList.toggle('narrow', !wide);
    const ok = $('#dlgOk'), cancel = $('#dlgCancel'), extra = $('#dlgExtra');
    ok.textContent = okText; ok.classList.toggle('danger', danger);
    cancel.textContent = cancelText; show(cancel, !hideCancel);
    extra.textContent = extraText || ''; show(extra, !!extraText);
    show($('#dlgModal'), true);
    const done = v => { show($('#dlgModal'), false); ok.onclick = cancel.onclick = extra.onclick = $('#dlgX').onclick = null; resolve(v); };
    ok.onclick = async () => { ok.disabled = true; try { const v = onOk ? await onOk() : true; if (v !== false) done(v); } finally { ok.disabled = false; } };
    cancel.onclick = () => done(null);
    extra.onclick = () => done('extra');
    $('#dlgX').onclick = () => done(null);
    const first = $('#dlgBody').querySelector('input:not([type=checkbox]),textarea,select');
    setTimeout(() => (first || ok).focus(), 30);
  });
}

export const confirmBox = (title, text, okText = 'OK', danger = false) => dialog({ title, html: `<p>${esc(text)}</p>`, okText, danger });

/* =================================================================
 * 4. KEY PASSPHRASE PROMPT
 * ================================================================= */
export function promptPassphrase(keyring, fp, userId) {
  return new Promise(resolve => {
    $('#passWho').textContent = (userId || 'Private key') + ' · ' + (fp ? fp.replace(/(.{4})/g, '$1 ').trim().slice(-24) : '');
    $('#passInput').value = '';
    $('#passErr').textContent = '';
    show($('#passModal'), true);
    setTimeout(() => $('#passInput').focus(), 30);
    const finish = v => { show($('#passModal'), false); $('#passOk').onclick = $('#passCancel').onclick = $('#passInput').onkeydown = null; resolve(v); };
    const go = async () => {
      $('#passOk').disabled = true; $('#passErr').textContent = 'Checking…';
      try { await keyring.unlock(fp, $('#passInput').value); finish(true); }
      catch (e) { $('#passErr').textContent = e.message; $('#passInput').select(); }
      finally { $('#passOk').disabled = false; }
    };
    $('#passOk').onclick = go;
    $('#passCancel').onclick = () => finish(false);
    $('#passInput').onkeydown = e => { if (e.key === 'Enter') go(); if (e.key === 'Escape') finish(false); };
  });
}

/** Run fn; if a key must be unlocked first, ask for its passphrase and try again. */
export async function withPassphrase(keyring, fn) {
  for (let i = 0; i < 4; i++) {
    try { return await fn(); }
    catch (e) {
      if (e.code !== 'NEED_PASSPHRASE') throw e;
      if (!(await promptPassphrase(keyring, e.fingerprint, e.userId))) throw Object.assign(new Error('Cancelled — key stays locked'), { code: 'CANCELLED' });
    }
  }
  throw new Error('Too many attempts');
}
