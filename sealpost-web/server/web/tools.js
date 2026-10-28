/* =====================================================================
 * Sealpost Web — tools.js  (PGP Tools, added 1.4.0)
 * ---------------------------------------------------------------------
 * Encrypt, sign, decrypt, verify or import pasted text — for messages
 * you write or receive somewhere else (chat, a web form, a document).
 * Everything happens in this browser tab; nothing is sent anywhere.
 *
 * Sections:
 *   1. Show the view (fills the "Sign with" list)
 *   2. Encrypt (optionally signed)
 *   3. Sign (cleartext signature)
 *   4. Decrypt / verify / import (detected automatically)
 * ===================================================================== */

import { $, esc, toast, copyText, withPassphrase } from './ui.js?v=1.11.2';
import { emailsOf } from './pgp.js?v=1.11.2';

export function initTools(ctx) {
  const { keyring } = ctx;
  const status = (html, kind = 'ok') => { $('#toolStatus').innerHTML = html ? `<div class="pgp-banner ${kind}"><div class="msg-txt">${html}</div></div>` : ''; };
  const busy = on => document.querySelectorAll('#toolsView .tool-actions button').forEach(b => { b.disabled = on; });

  /* =================================================================
   * 1. SHOW
   * ================================================================= */
  function showTools() {
    const sel = $('#toolSigner');
    const cur = sel.value;
    const opts = ['<option value="">(don\'t sign)</option>'];
    for (const [, k] of keyring.privateKeys) for (const e of emailsOf(k)) opts.push(`<option value="${esc(e)}">${esc(k.getUserIDs()[0])}</option>`);
    sel.innerHTML = opts.join('');
    if (cur && [...sel.options].some(o => o.value === cur)) sel.value = cur;
    else if (sel.options.length > 1) sel.selectedIndex = 1;
  }

  /* =================================================================
   * 2. ENCRYPT — to the recipients' keys (+ yourself when signing)
   * ================================================================= */
  $('#toolEncrypt').addEventListener('click', async () => {
    const text = $('#toolIn').value;
    const recipients = $('#toolRecipients').value.split(/[,;\s]+/).map(s => s.trim().toLowerCase()).filter(s => s.includes('@'));
    if (!text.trim()) return status('Type or paste the text to encrypt.', 'warn');
    if (!recipients.length) return status('Enter at least one recipient email address.', 'warn');
    busy(true);
    try {
      const signWith = $('#toolSigner').value;
      const signerFp = signWith ? await keyring.findSecretFor(signWith) : null;
      const armored = await withPassphrase(keyring, () => keyring.encrypt({ data: new TextEncoder().encode(text), recipients, signerFp, encryptToSelfFp: signerFp }));
      $('#toolOut').value = armored;
      status(`🔒 Encrypted for ${esc(recipients.join(', '))}${signerFp ? ' and signed' : ''}. Copy it below.`);
    } catch (e) {
      if (e.code === 'MISSING_KEYS') status(`No usable key for: <b>${esc(e.missing.join(', '))}</b>. Find it online or import it under Keys.`, 'bad');
      else if (e.code !== 'CANCELLED') status(esc(e.message), 'bad');
    } finally { busy(false); }
  });

  /* =================================================================
   * 3. SIGN — readable text with a signature block anyone can check
   * ================================================================= */
  $('#toolSign').addEventListener('click', async () => {
    const text = $('#toolIn').value;
    const signWith = $('#toolSigner').value;
    if (!text.trim()) return status('Type or paste the text to sign.', 'warn');
    if (!signWith) return status('Choose a key under "Sign with".', 'warn');
    busy(true);
    try {
      const fp = await keyring.findSecretFor(signWith);
      if (!fp) throw new Error('No usable private key for ' + signWith);
      $('#toolOut').value = await withPassphrase(keyring, () => keyring.signCleartext({ text, signerFp: fp }));
      status('✍ Signed. Copy it below.');
    } catch (e) { if (e.code !== 'CANCELLED') status(esc(e.message), 'bad'); }
    finally { busy(false); }
  });

  /* =================================================================
   * 4. DECRYPT / VERIFY / IMPORT
   * ================================================================= */
  const sigLines = sigs => sigs.map(s => s.valid
    ? `<div>✔ Good signature from <b>${esc(s.signer)}</b>${s.trust === 'verified' || s.trust === 'ultimate' ? '' : ' <span class="muted">(key not yet verified)</span>'}<div class="sub">${esc(s.fingerprint)}</div></div>`
    : s.unknownKey ? `<div>? Signed with a key you don't have (ID ${esc(s.keyId)})</div>`
      : `<div><b>✖ BAD SIGNATURE</b> — ${esc(s.signer || s.keyId)}: ${esc(s.error || '')}</div>`).join('');

  $('#toolProcess').addEventListener('click', async () => {
    const text = $('#toolIn').value;
    busy(true);
    try {
      if (/-----BEGIN PGP MESSAGE-----/.test(text)) {
        const block = text.match(/-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/)[0];
        const r = await withPassphrase(keyring, () => keyring.decrypt(block));
        $('#toolOut').value = new TextDecoder().decode(r.data);
        const bad = r.signatures.some(s => !s.valid && !s.unknownKey);
        status('🔓 Decrypted in this browser.' + sigLines(r.signatures), bad ? 'bad' : 'ok');
      } else if (/-----BEGIN PGP SIGNED MESSAGE-----/.test(text)) {
        const block = text.match(/-----BEGIN PGP SIGNED MESSAGE-----[\s\S]*?-----END PGP SIGNATURE-----/);
        if (!block) throw new Error('The signature block is incomplete');
        const r = await keyring.verifyCleartext(block[0]);
        $('#toolOut').value = r.text;
        const ok = r.signatures.length && r.signatures.every(s => s.valid);
        status(sigLines(r.signatures) || 'No signature found.', ok ? 'ok' : r.signatures.some(s => !s.valid && !s.unknownKey) ? 'bad' : 'warn');
      } else if (/-----BEGIN PGP (PUBLIC|PRIVATE) KEY BLOCK-----/.test(text)) {
        if (await ctx.importKeys(text)) status('🔑 Key imported — it syncs to all your devices.');
      } else {
        status('No PGP block found. Paste a message starting with -----BEGIN PGP …', 'warn');
      }
    } catch (e) { if (e.code !== 'CANCELLED') status(esc(e.message), 'bad'); }
    finally { busy(false); }
  });

  $('#toolPaste').addEventListener('click', async () => {
    try { $('#toolIn').value = await navigator.clipboard.readText(); }
    catch { toast('Your browser blocked reading the clipboard — paste with Ctrl+V instead.', 'err'); }
  });
  $('#toolClear').addEventListener('click', () => { $('#toolIn').value = ''; $('#toolOut').value = ''; status(''); });
  $('#toolCopy').addEventListener('click', async () => { if ($('#toolOut').value) { await copyText($('#toolOut').value); toast('Copied.'); } });

  return { showTools };
}
