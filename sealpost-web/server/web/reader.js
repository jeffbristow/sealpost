/* =====================================================================
 * Sealpost Web — reader.js
 * ---------------------------------------------------------------------
 * Opens a raw email in the browser, the same way Sealpost does on your
 * PC (reader.js there):
 *   - PGP/MIME encrypted (multipart/encrypted)   -> decrypt
 *   - PGP/MIME signed (multipart/signed)         -> verify exact bytes
 *   - nested sign + encrypt, protected subjects
 *   - inline PGP blocks and cleartext signatures
 *   - attachments, encrypted attachments, key attachments, Autocrypt
 * Decrypted content never leaves the browser.
 *
 * Sections:
 *   1. Byte <-> "binary string" helpers
 *   2. Minimal MIME helpers (headers, boundaries, transfer decoding)
 *   3. PGP/MIME layers (recursive)
 *   4. Building the message view
 *   5. Reopening drafts (1.2.0)
 * ===================================================================== */

import PostalMime from './vendor/postal-mime.js';

/* =================================================================
 * 1. BYTES <-> BINARY STRINGS (one char per byte, keeps bytes 1:1)
 * ================================================================= */
export function bytesToBin(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return s;
}

export function binToBytes(s) {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

const toCRLF = s => s.replace(/\r?\n/g, '\r\n');

/* =================================================================
 * 2. MIME HELPERS
 * ================================================================= */
function splitEntity(s) {
  let idx = s.indexOf('\r\n\r\n'), sepLen = 4;
  const lf = s.indexOf('\n\n');
  if (idx === -1 || (lf !== -1 && lf < idx)) { idx = lf; sepLen = 2; }
  if (idx === -1) return { headers: new Map(), body: '' };
  const headers = new Map();
  s.slice(0, idx).replace(/\r?\n[ \t]+/g, ' ').split(/\r?\n/).forEach(line => {
    const c = line.indexOf(':');
    if (c > 0) {
      const k = line.slice(0, c).trim().toLowerCase();
      if (!headers.has(k)) headers.set(k, line.slice(c + 1).trim());
    }
  });
  return { headers, body: s.slice(idx + sepLen) };
}

/** 'multipart/signed; protocol="x"; boundary=abc' -> { type, params } */
function parseContentType(v) {
  const out = { type: 'text/plain', params: {} };
  if (!v) return out;
  const parts = [];
  let cur = '', q = false;
  for (const ch of v) {
    if (ch === '"') q = !q;
    if (ch === ';' && !q) { parts.push(cur); cur = ''; } else cur += ch;
  }
  parts.push(cur);
  out.type = parts.shift().trim().toLowerCase();
  for (const p of parts) {
    const i = p.indexOf('=');
    if (i < 0) continue;
    out.params[p.slice(0, i).trim().toLowerCase()] = p.slice(i + 1).trim().replace(/^"(.*)"$/, '$1');
  }
  return out;
}

const escapeRe = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Raw parts of a multipart body, each without the CRLF before the next boundary (RFC 3156). */
function splitMultipart(body, bnd) {
  const re = new RegExp('(^|\\r?\\n)' + escapeRe('--' + bnd) + '(--)?[ \\t]*(\\r?\\n|$)', 'g');
  const parts = [];
  let m, lastEnd = null;
  while ((m = re.exec(body)) !== null) {
    if (lastEnd !== null) parts.push(body.slice(lastEnd, m.index));
    if (m[2] === '--') break;
    lastEnd = m.index + m[0].length;
  }
  return parts;
}

function decodeBody(body, cte) {
  cte = (cte || '7bit').toLowerCase();
  if (cte === 'base64') return binToBytes(atob(body.replace(/[^A-Za-z0-9+/=]/g, '')));
  if (cte === 'quoted-printable') return binToBytes(body.replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16))));
  return binToBytes(body);
}

/* =================================================================
 * 3. PGP/MIME LAYERS — returns the innermost content (binary string)
 *    or null when it couldn't be opened.
 * ================================================================= */
async function unwrap(raw, keyring, state, depth = 0) {
  if (depth > 4) return raw;
  const { headers, body } = splitEntity(raw);
  const ct = parseContentType(headers.get('content-type'));
  const proto = (ct.params.protocol || '').toLowerCase();

  /* ----- encrypted layer ----- */
  if (ct.type === 'multipart/encrypted' && proto.includes('pgp-encrypted')) {
    state.encrypted = true;
    const parts = splitMultipart(body, ct.params.boundary || '');
    if (parts.length < 2) { state.errors.push('Malformed PGP/MIME encrypted message'); return null; }
    const p = splitEntity(parts[1]);
    const armored = new TextDecoder().decode(decodeBody(p.body, p.headers.get('content-transfer-encoding')));
    try {
      const res = await keyring.decrypt(armored);
      state.decrypted = true;
      if (res.signatures.length) { state.signed = true; state.signatures.push(...res.signatures); }
      return unwrap(bytesToBin(res.data), keyring, state, depth + 1);
    } catch (e) { captureError(e, state); return null; }
  }

  /* ----- signed layer ----- */
  if (ct.type === 'multipart/signed' && proto.includes('pgp-signature')) {
    state.signed = true;
    const parts = splitMultipart(body, ct.params.boundary || '');
    if (parts.length < 2) { state.errors.push('Malformed PGP/MIME signed message'); return raw; }
    const sp = splitEntity(parts[1]);
    const sig = new TextDecoder().decode(decodeBody(sp.body, sp.headers.get('content-transfer-encoding')));
    try {
      state.signatures.push(...(await keyring.verifyDetached(binToBytes(toCRLF(parts[0])), sig)));
    } catch (e) { state.errors.push('Signature check failed: ' + e.message); }
    return unwrap(parts[0], keyring, state, depth + 1);
  }

  /* ----- list footers: signed/encrypted part inside multipart/mixed ----- */
  if (ct.type === 'multipart/mixed' && depth === 0) {
    const parts = splitMultipart(body, ct.params.boundary || '');
    if (parts.length >= 1) {
      const fct = parseContentType(splitEntity(parts[0]).headers.get('content-type'));
      if (fct.type === 'multipart/signed' || fct.type === 'multipart/encrypted') {
        state.notes.push('Only the first part of this message is protected by PGP; the rest (e.g. a list footer) is not.');
        return unwrap(parts[0], keyring, state, depth + 1);
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
 * 4. MESSAGE VIEW
 * ================================================================= */
const htmlToText = html => {
  const doc = new DOMParser().parseFromString(html, 'text/html');
  doc.querySelectorAll('script,style,head').forEach(n => n.remove());
  doc.querySelectorAll('br').forEach(n => n.replaceWith('\n'));
  doc.querySelectorAll('p,div,li,tr,h1,h2,h3,h4').forEach(n => n.append('\n'));
  return (doc.body ? doc.body.textContent : '').replace(/\n{3,}/g, '\n\n').trim();
};

const bytesHead = (u8, n = 2000) => new TextDecoder().decode(u8.subarray(0, n));

export async function readMessage(rawBytes, keyring) {
  const state = { encrypted: false, decrypted: false, signed: false, signatures: [], errors: [], notes: [], needPassphrase: null, inline: false, protectedSubject: false };
  const raw = bytesToBin(rawBytes);
  const outer = await PostalMime.parse(rawBytes);
  const content = await unwrap(raw, keyring, state);

  let parsed = outer;
  if (content && content !== raw) parsed = await PostalMime.parse(binToBytes(content));

  let subject = outer.subject || '';
  if (state.decrypted && parsed !== outer && parsed.subject) { subject = parsed.subject; state.protectedSubject = true; }

  let text = content ? (parsed.text || '') : '';
  let html = content ? (parsed.html || null) : null;
  let attachments = content ? [...(parsed.attachments || [])] : [];

  /* ----- inline PGP inside the text ----- */
  if (content && /-----BEGIN PGP MESSAGE-----/.test(text)) {
    state.inline = true; state.encrypted = true;
    const block = text.match(/-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/)[0];
    try {
      const res = await keyring.decrypt(block);
      state.decrypted = true;
      if (res.signatures.length) { state.signed = true; state.signatures.push(...res.signatures); }
      let inner = new TextDecoder().decode(res.data);
      if (/^content-type:/im.test(inner.slice(0, 500))) {
        const p2 = await PostalMime.parse(res.data);
        inner = p2.text || inner;
        attachments.push(...(p2.attachments || []));
      }
      text = text.replace(block, inner);
      html = null;
    } catch (e) { captureError(e, state); }
  } else if (content && /-----BEGIN PGP SIGNED MESSAGE-----/.test(text)) {
    state.inline = true; state.signed = true;
    const block = text.match(/-----BEGIN PGP SIGNED MESSAGE-----[\s\S]*?-----END PGP SIGNATURE-----/);
    if (block) {
      try {
        const r = await keyring.verifyCleartext(block[0]);
        state.signatures.push(...r.signatures);
        text = text.replace(block[0], r.text);
        html = null;
      } catch (e) { state.errors.push('Inline signature check failed: ' + e.message); }
    }
  }

  if (html && !String(text || '').trim()) { try { text = htmlToText(html); } catch { /* leave empty */ } }

  const fromAddr = ((outer.from && outer.from.address) || '').toLowerCase();
  for (const s of state.signatures) s.matchesSender = s.signerEmails.includes(fromAddr);

  /* ----- attachments (without the PGP/MIME plumbing parts) ----- */
  const list = attachments
    .filter(a => !['application/pgp-signature', 'application/pgp-encrypted'].includes((a.mimeType || '').toLowerCase()))
    .map((a, i) => {
      const bytes = new Uint8Array(a.content);
      const head = bytesHead(bytes);
      const filename = a.filename || ('attachment-' + (i + 1));
      return {
        index: i, filename,
        contentType: a.mimeType || 'application/octet-stream',
        size: bytes.length,
        cid: a.contentId ? a.contentId.replace(/[<>]/g, '') : null,
        inline: a.disposition === 'inline' && !!a.contentId,
        bytes,
        isKey: a.mimeType === 'application/pgp-keys' || head.includes('-----BEGIN PGP PUBLIC KEY BLOCK-----'),
        isEncrypted: /\.(pgp|gpg)$/i.test(filename) || head.includes('-----BEGIN PGP MESSAGE-----')
      };
    });

  /* ----- inline images: cid: -> data: ----- */
  if (html) {
    for (const a of list) {
      if (!a.cid) continue;
      let b64 = '';
      for (let i = 0; i < a.bytes.length; i += 0x8000) b64 += String.fromCharCode.apply(null, a.bytes.subarray(i, i + 0x8000));
      html = html.split('cid:' + a.cid).join('data:' + a.contentType + ';base64,' + btoa(b64));
    }
  }

  /* ----- Autocrypt header ----- */
  let autocryptKey = null;
  const ac = (outer.headers || []).find(h => h.key === 'autocrypt');
  if (ac) { const m = String(ac.value).match(/keydata=([A-Za-z0-9+/=\s]+)/); if (m) autocryptKey = m[1].replace(/\s+/g, ''); }

  const addrList = v => (v ? [].concat(v) : []).flatMap(a => a.group ? a.group : [a]).filter(a => a && a.address).map(a => ({ name: a.name || '', address: a.address.toLowerCase() }));
  return {
    subject,
    from: addrList(outer.from),
    to: addrList(outer.to),
    cc: addrList(outer.cc),
    replyTo: addrList(outer.replyTo),
    date: outer.date ? new Date(outer.date).toISOString() : null,
    messageId: outer.messageId || null,
    text, html,
    attachments: list,
    autocryptKey,
    rawSize: rawBytes.length,
    pgp: state
  };
}

/* =================================================================
 * 5. DRAFTS (1.2.0) — reopen a saved draft in the composer
 *    Works for drafts saved by Sealpost Web and by Sealpost on your PC.
 * ================================================================= */
export async function readDraft(rawBytes, keyring) {
  const state = { encrypted: false, decrypted: false, signed: false, signatures: [], errors: [], notes: [], needPassphrase: null };
  const raw = bytesToBin(rawBytes);
  const content = await unwrap(raw, keyring, state);
  if (state.needPassphrase) throw Object.assign(new Error('Passphrase required'), { code: 'NEED_PASSPHRASE', fingerprint: state.needPassphrase.fingerprint, userId: state.needPassphrase.userId });
  if (!content) throw new Error(state.errors.join(' · ') || 'Could not open this draft');

  const outer = await PostalMime.parse(rawBytes);
  const inner = content === raw ? outer : await PostalMime.parse(binToBytes(content));
  const hdr = name => {
    const h = (inner.headers || []).find(x => x.key === name) || (outer.headers || []).find(x => x.key === name);
    if (!h) return '';
    return decodeWordsSafe(h.value);
  };
  let meta = {};
  try { meta = JSON.parse(new TextDecoder().decode(binToBytes(atob(hdr('x-sealpost-draft').replace(/\s+/g, ''))))) || {}; } catch { meta = {}; }

  let text = inner.text || '';
  const html = inner.html || null;
  if (html && !text.trim()) text = htmlToText(html);
  let bodyHtml = null;
  if (html && meta.format === 'rich') { const m = html.match(/<body[^>]*>([\s\S]*)<\/body>/i); bodyHtml = m ? m[1] : html; }

  return {
    to: hdr('to'), cc: hdr('cc'), bcc: hdr('bcc'),
    subject: inner.subject || hdr('subject') || (state.encrypted ? '' : outer.subject || ''),
    text: text.replace(/\r\n?/g, '\n'), html: bodyHtml, meta,
    encrypted: state.encrypted,
    attachments: (inner.attachments || [])
      .filter(a => !['application/pgp-signature', 'application/pgp-encrypted'].includes((a.mimeType || '').toLowerCase()))
      .map(a => ({ filename: a.filename || 'attachment', contentType: a.mimeType || 'application/octet-stream', bytes: new Uint8Array(a.content) }))
  };
}

/** "=?UTF-8?B?…?=" words inside a header value -> text */
function decodeWordsSafe(v) {
  return String(v || '').replace(/\r?\n[ \t]+/g, ' ').replace(/=\?([^?]+)\?([bqBQ])\?([^?]*)\?=(\s+(?==\?))?/g, (_, cs, enc, data) => {
    try {
      const bytes = enc.toUpperCase() === 'B' ? binToBytes(atob(data)) : binToBytes(data.replace(/_/g, ' ').replace(/=([0-9A-F]{2})/gi, (m, h) => String.fromCharCode(parseInt(h, 16))));
      return new TextDecoder(cs.toLowerCase()).decode(bytes);
    } catch { return data; }
  });
}
