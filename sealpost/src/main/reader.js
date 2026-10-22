/* =====================================================================
 * Sealpost — reader.js
 * ---------------------------------------------------------------------
 * Opens a raw email for display and handles all incoming PGP:
 *
 *   - PGP/MIME encrypted   (multipart/encrypted)  -> decrypt
 *   - PGP/MIME signed      (multipart/signed)     -> verify exact bytes
 *   - sign-then-encrypt combinations (nested)
 *   - Inline PGP blocks in the text body (older clients)
 *   - Inline cleartext signatures
 *   - Protected (encrypted) subject lines
 *   - Encrypted attachments (.pgp/.gpg/.asc) and key attachments
 *   - Autocrypt headers (sender's key offered for import)
 *
 * Output is a plain "view" object the UI can render directly.
 * ===================================================================== */

const { simpleParser } = require('mailparser');
const { convert: htmlToText } = require('html-to-text'); // ships with mailparser
const mime = require('./mime');

/* =================================================================
 * 1. PGP/MIME LAYER ANALYSIS (recursive)
 * ================================================================= */
async function unwrap(raw, pgp, state, depth = 0) {
  if (depth > 4) return raw;
  const { headers, body } = mime.splitEntity(raw);
  const ct = mime.parseContentType(headers.get('content-type'));
  const proto = (ct.params.protocol || '').toLowerCase();

  /* ----- Encrypted layer ----- */
  if (ct.type === 'multipart/encrypted' && proto.includes('pgp-encrypted')) {
    state.encrypted = true;
    const parts = mime.splitMultipart(body, ct.params.boundary);
    if (parts.length < 2) { state.errors.push('Malformed PGP/MIME encrypted message'); return null; }
    const p = mime.splitEntity(parts[1]);
    const armored = mime.decodeBody(p.body, p.headers.get('content-transfer-encoding')).toString('utf8');
    try {
      const res = await pgp.decrypt(armored);
      state.decrypted = true;
      if (res.signatures.length) { state.signed = true; state.signatures.push(...res.signatures); }
      return unwrap(res.data, pgp, state, depth + 1);
    } catch (e) {
      captureError(e, state);
      return null;
    }
  }

  /* ----- Signed layer ----- */
  if (ct.type === 'multipart/signed' && proto.includes('pgp-signature')) {
    state.signed = true;
    const s = Buffer.isBuffer(raw) ? raw.toString('binary') : raw;
    const { body: b } = mime.splitEntity(s);
    const parts = mime.splitMultipart(b, ct.params.boundary);
    if (parts.length < 2) { state.errors.push('Malformed PGP/MIME signed message'); return raw; }
    const signedPart = parts[0];
    const sp = mime.splitEntity(parts[1]);
    const sig = mime.decodeBody(sp.body, sp.headers.get('content-transfer-encoding')).toString('utf8');
    try {
      // RFC 3156: verify over the part with canonical CRLF line endings
      const data = Buffer.from(mime.toCRLF(signedPart), 'binary');
      state.signatures.push(...(await pgp.verifyDetached({ data, armoredSignature: sig })));
    } catch (e) {
      state.errors.push('Signature check failed: ' + e.message);
    }
    return unwrap(Buffer.from(signedPart, 'binary'), pgp, state, depth + 1);
  }

  /* ----- Mailing lists sometimes wrap a signed part inside multipart/mixed ----- */
  if (ct.type === 'multipart/mixed' && depth === 0) {
    const parts = mime.splitMultipart(body, ct.params.boundary || '');
    if (parts.length >= 1) {
      const first = mime.splitEntity(parts[0]);
      const fct = mime.parseContentType(first.headers.get('content-type'));
      if (fct.type === 'multipart/signed' || fct.type === 'multipart/encrypted') {
        state.notes.push('Only the first part of this message is protected by PGP; the rest (e.g. a list footer) is not.');
        return unwrap(Buffer.from(parts[0], 'binary'), pgp, state, depth + 1);
      }
    }
  }
  return raw;
}

function captureError(e, state) {
  if (e.code === 'NEED_PASSPHRASE') state.needPassphrase = { fingerprint: e.fingerprint, userId: e.userId };
  else if (e.code === 'NO_SECRET_KEY') state.errors.push(e.message);
  else state.errors.push('Decryption failed: ' + e.message);
}

/* =================================================================
 * 2. FULL MESSAGE VIEW
 * ================================================================= */
async function readMessage(rawBuf, pgp) {
  const state = {
    encrypted: false, decrypted: false, signed: false,
    signatures: [], errors: [], notes: [], needPassphrase: null,
    inline: false, protectedSubject: false
  };

  const outer = await simpleParser(rawBuf, { skipHtmlToText: false });
  const contentRaw = await unwrap(rawBuf, pgp, state);

  let parsed = outer;
  if (contentRaw && contentRaw !== rawBuf) {
    parsed = await simpleParser(Buffer.isBuffer(contentRaw) ? contentRaw : Buffer.from(contentRaw, 'binary'));
  }

  let subject = outer.subject || '';
  // protected headers: the real subject lives inside the encrypted part
  if (state.decrypted && parsed !== outer && parsed.subject) {
    subject = parsed.subject;
    state.protectedSubject = true;
  }

  let text = contentRaw ? (parsed.text || '') : '';
  let html = contentRaw ? (parsed.html || null) : null;

  /* ----- Inline PGP inside the text body ----- */
  if (contentRaw && /-----BEGIN PGP MESSAGE-----/.test(text)) {
    state.inline = true;
    state.encrypted = true;
    const block = text.match(/-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/)[0];
    try {
      const res = await pgp.decrypt(block);
      state.decrypted = true;
      if (res.signatures.length) { state.signed = true; state.signatures.push(...res.signatures); }
      let inner = res.data.toString('utf8');
      // some clients put MIME inside the inline block
      if (/^content-type:/im.test(inner.slice(0, 500))) {
        const p2 = await simpleParser(res.data);
        inner = p2.text || inner;
        parsed.attachments = [...(parsed.attachments || []), ...(p2.attachments || [])];
      }
      text = text.replace(block, inner);
      html = null; // show decrypted text, not the armored html version
    } catch (e) { captureError(e, state); }
  } else if (contentRaw && /-----BEGIN PGP SIGNED MESSAGE-----/.test(text)) {
    state.inline = true;
    state.signed = true;
    const block = text.match(/-----BEGIN PGP SIGNED MESSAGE-----[\s\S]*?-----END PGP SIGNATURE-----/);
    if (block) {
      try {
        const r = await pgp.verifyCleartext(block[0]);
        state.signatures.push(...r.signatures);
        text = text.replace(block[0], r.text);
        html = null;
      } catch (e) { state.errors.push('Inline signature check failed: ' + e.message); }
    }
  }

  /* ----- FIX 1.0.1: HTML-only emails (e.g. Proton) have no plain-text part.
   *       Build one so the Plain text tab and reply quoting aren't empty. ----- */
  if (html && !String(text || '').trim()) {
    try {
      text = htmlToText(html, { wordwrap: false, selectors: [{ selector: 'img', format: 'skip' }, { selector: 'a', options: { hideLinkHrefIfSameAsText: true } }] });
    } catch { /* leave text empty */ }
  }

  /* ----- Does the signer match the From address? ----- */
  const fromAddr = (outer.from && outer.from.value[0] && outer.from.value[0].address || '').toLowerCase();
  for (const s of state.signatures) s.matchesSender = s.signerEmails.includes(fromAddr);

  /* ----- Attachments (skip the PGP/MIME plumbing parts) ----- */
  const attachments = (contentRaw ? parsed.attachments || [] : [])
    .filter(a => !['application/pgp-signature', 'application/pgp-encrypted'].includes(a.contentType))
    .map((a, i) => {
      const head = a.content.slice(0, 2000).toString('utf8');
      return {
        index: i,
        filename: a.filename || ('attachment-' + (i + 1)),
        contentType: a.contentType,
        size: a.size || a.content.length,
        cid: a.contentId ? a.contentId.replace(/[<>]/g, '') : null,
        inline: a.contentDisposition === 'inline' && !!a.contentId,
        content: a.content,
        isKey: a.contentType === 'application/pgp-keys' || head.includes('-----BEGIN PGP PUBLIC KEY BLOCK-----'),
        isEncrypted: /\.(pgp|gpg)$/i.test(a.filename || '') || head.includes('-----BEGIN PGP MESSAGE-----')
      };
    });

  /* ----- Inline images: swap cid: links for embedded data ----- */
  if (html) {
    for (const a of attachments) {
      if (a.cid) html = html.split('cid:' + a.cid).join('data:' + a.contentType + ';base64,' + a.content.toString('base64'));
    }
  }

  /* ----- Autocrypt header: sender's key offered for import ----- */
  let autocryptKey = null;
  const ac = outer.headers.get('autocrypt');
  if (ac) {
    const s = typeof ac === 'string' ? ac : (ac.value || '');
    const m = String(s).match(/keydata=([A-Za-z0-9+/=\s]+)/);
    if (m) autocryptKey = m[1].replace(/\s+/g, '');
  }

  return {
    subject,
    from: outer.from ? outer.from.value : [],
    to: outer.to ? [].concat(outer.to).flatMap(x => x.value) : [],
    cc: outer.cc ? [].concat(outer.cc).flatMap(x => x.value) : [],
    replyTo: outer.replyTo ? outer.replyTo.value : [],
    date: outer.date ? outer.date.toISOString() : null,
    messageId: outer.messageId || null,
    references: outer.references ? [].concat(outer.references).join(' ') : null,
    text,
    html,
    attachments,
    autocryptKey,
    pgp: state
  };
}

/* =================================================================
 * 3. DRAFTS (1.1.0) — reopen a saved draft in the composer
 * ================================================================= */
async function readDraft(rawBuf, pgp) {
  const state = { encrypted: false, decrypted: false, signed: false, signatures: [], errors: [], notes: [], needPassphrase: null };
  const contentRaw = await unwrap(rawBuf, pgp, state);
  if (state.needPassphrase) {
    const err = new Error('Passphrase required');
    err.code = 'NEED_PASSPHRASE'; err.fingerprint = state.needPassphrase.fingerprint; err.userId = state.needPassphrase.userId;
    throw err;
  }
  if (!contentRaw) throw new Error(state.errors.join(' · ') || 'Could not open this draft');

  const outer = await simpleParser(rawBuf);
  const inner = contentRaw === rawBuf ? outer : await simpleParser(Buffer.isBuffer(contentRaw) ? contentRaw : Buffer.from(contentRaw, 'binary'));
  const hdr = name => {
    const v = inner.headers.get(name) ?? outer.headers.get(name);
    if (!v) return '';
    if (typeof v === 'string') return v;
    if (v.text) return v.text;            // address objects
    if (v.value && Array.isArray(v.value)) return v.value.map(a => a.name ? `${a.name} <${a.address}>` : a.address).join(', ');
    return String(v.value || v);
  };
  let meta = {};
  try { meta = JSON.parse(Buffer.from(hdr('x-sealpost-draft'), 'base64').toString('utf8')) || {}; } catch { meta = {}; }

  let text = inner.text || '';
  const html = inner.html || null;
  if (html && !text.trim()) { try { text = htmlToText(html, { wordwrap: false }); } catch { /* ignore */ } }

  // body of a rich draft: just the content inside <body>
  let bodyHtml = null;
  if (html && meta.format === 'rich') {
    const m = html.match(/<body[^>]*>([\s\S]*)<\/body>/i);
    bodyHtml = m ? m[1] : html;
  }

  return {
    to: hdr('to'), cc: hdr('cc'), bcc: hdr('bcc'),
    subject: inner.subject || hdr('subject') || (state.encrypted ? '' : outer.subject || ''),
    text, html: bodyHtml, meta,
    encrypted: state.encrypted,
    attachments: (inner.attachments || [])
      .filter(a => !['application/pgp-signature', 'application/pgp-encrypted'].includes(a.contentType))
      .map(a => ({ filename: a.filename || 'attachment', contentType: a.contentType, size: a.size || a.content.length, content: a.content.toString('base64') }))
  };
}

module.exports = { readMessage, readDraft };
