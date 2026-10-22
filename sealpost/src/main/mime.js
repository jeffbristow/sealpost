/* =====================================================================
 * Sealpost — mime.js
 * ---------------------------------------------------------------------
 * Builds and dissects raw MIME messages.
 *
 * PGP/MIME (RFC 3156) needs byte-exact control over the message body,
 * so instead of letting the SMTP library assemble the email we build
 * the raw message here and hand it over finished.
 *
 * Sections:
 *   1. Low-level helpers (CRLF, base64 wrapping, header encoding)
 *   2. Builders  — plain body, outer message, PGP/MIME signed/encrypted
 *   3. Parsers   — header split, multipart split, transfer decoding
 * ===================================================================== */

const crypto = require('crypto');
const mimeFuncs = require('nodemailer/lib/mime-funcs');
const addressparser = require('nodemailer/lib/addressparser');

/* =================================================================
 * 1. LOW-LEVEL HELPERS
 * ================================================================= */
const CRLF = '\r\n';

const toCRLF = s => s.replace(/\r?\n/g, CRLF);

const boundary = tag => '----=_Sealpost_' + tag + '_' + crypto.randomBytes(12).toString('hex');

function b64Wrap(buf) {
  return Buffer.from(buf).toString('base64').replace(/.{1,76}/g, '$&' + CRLF).replace(/\r\n$/, '');
}

// RFC 2047 encode a header value only if it contains non-ASCII
function encHeader(v) {
  v = String(v || '').replace(/[\r\n]+/g, ' ');
  return mimeFuncs.isPlainText(v) ? v : mimeFuncs.encodeWords(v, 'B', 52);
}

// "Name" <addr>, encoded safely
function formatAddress({ name, address }) {
  if (!name) return address;
  const n = mimeFuncs.isPlainText(name) ? mimeFuncs.quoteString(name) : mimeFuncs.encodeWord(name, 'B', 52);
  return n + ' <' + address + '>';
}

function parseAddressList(str) {
  return addressparser(String(str || ''), { flatten: true })
    .filter(a => a.address && a.address.includes('@'))
    .map(a => ({ name: a.name || '', address: a.address.trim() }));
}

function encodeFilename(name) {
  return mimeFuncs.isPlainText(name)
    ? 'filename="' + name.replace(/"/g, '') + '"'
    : "filename*=UTF-8''" + encodeURIComponent(name);
}

/* =================================================================
 * 2. BUILDERS
 * ================================================================= */

/**
 * Inner content entity: text (+ optional html) (+ attachments).
 * Returns a MIME entity string (headers + body, CRLF line endings).
 * protectedHeaders: when set, adds RFC "protected headers" (encrypted
 * subject) so the real subject travels inside the encryption.
 */
function buildContentEntity({ text, html, attachments = [], protectedHeaders = null }) {
  const textPart =
    'Content-Type: text/plain; charset=utf-8' + CRLF +
    'Content-Transfer-Encoding: base64' + CRLF + CRLF +
    b64Wrap(Buffer.from(toCRLF(text || ''), 'utf8'));

  let body = textPart;

  if (html) {
    const b = boundary('alt');
    body =
      'Content-Type: multipart/alternative; boundary="' + b + '"' + CRLF + CRLF +
      '--' + b + CRLF + textPart + CRLF +
      '--' + b + CRLF +
      'Content-Type: text/html; charset=utf-8' + CRLF +
      'Content-Transfer-Encoding: base64' + CRLF + CRLF +
      b64Wrap(Buffer.from(html, 'utf8')) + CRLF +
      '--' + b + '--';
  }

  const phLines = protectedHeaders
    ? Object.entries(protectedHeaders).map(([k, v]) => k + ': ' + encHeader(v)).join(CRLF) + CRLF
    : '';

  if (!attachments.length && !protectedHeaders) return body;

  // Wrap in multipart/mixed (also needed to carry protected headers)
  const b = boundary('mix');
  let out =
    'Content-Type: multipart/mixed; boundary="' + b + '"' + (protectedHeaders ? '; protected-headers="v1"' : '') + CRLF +
    phLines + CRLF +
    '--' + b + CRLF + body + CRLF;

  for (const a of attachments) {
    const ct = a.contentType || mimeFuncs.detectMimeType(a.filename) || 'application/octet-stream';
    out +=
      '--' + b + CRLF +
      'Content-Type: ' + ct + '; name="' + (mimeFuncs.isPlainText(a.filename) ? a.filename.replace(/"/g, '') : encHeader(a.filename)) + '"' + CRLF +
      'Content-Disposition: attachment; ' + encodeFilename(a.filename) + CRLF +
      'Content-Transfer-Encoding: base64' + CRLF + CRLF +
      b64Wrap(a.content) + CRLF;
  }
  out += '--' + b + '--';
  return out;
}

/**
 * Outer message: envelope headers + a body entity (which carries its own
 * Content-Type header lines at the top).
 */
function buildMessage({ from, to = [], cc = [], bcc = [], subject, inReplyTo, references, entity, includeBcc = false }) {
  const domain = (from.address.split('@')[1] || 'localhost').replace(/[^a-z0-9.-]/gi, '');
  const messageId = '<' + crypto.randomUUID() + '@' + domain + '>';
  const h = [];
  h.push('From: ' + formatAddress(from));
  if (to.length) h.push('To: ' + to.map(formatAddress).join(', '));
  if (cc.length) h.push('Cc: ' + cc.map(formatAddress).join(', '));
  if (includeBcc && bcc.length) h.push('Bcc: ' + bcc.map(formatAddress).join(', '));
  h.push('Subject: ' + encHeader(subject || ''));
  h.push('Date: ' + new Date().toUTCString().replace('GMT', '+0000'));
  h.push('Message-ID: ' + messageId);
  if (inReplyTo) h.push('In-Reply-To: ' + inReplyTo);
  if (references) h.push('References: ' + references);
  h.push('MIME-Version: 1.0');
  h.push('X-Mailer: Sealpost 1.0');
  return { raw: h.join(CRLF) + CRLF + toCRLF(entity) + CRLF, messageId };
}

/** multipart/encrypted wrapper around an armored PGP message. */
function buildEncryptedEntity(armored) {
  const b = boundary('enc');
  return (
    'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="' + b + '"' + CRLF + CRLF +
    'This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)' + CRLF +
    '--' + b + CRLF +
    'Content-Type: application/pgp-encrypted' + CRLF +
    'Content-Description: PGP/MIME version identification' + CRLF + CRLF +
    'Version: 1' + CRLF + CRLF +
    '--' + b + CRLF +
    'Content-Type: application/octet-stream; name="encrypted.asc"' + CRLF +
    'Content-Description: OpenPGP encrypted message' + CRLF +
    'Content-Disposition: inline; filename="encrypted.asc"' + CRLF + CRLF +
    toCRLF(armored).trim() + CRLF + CRLF +
    '--' + b + '--'
  );
}

/** multipart/signed wrapper: signedEntity must be the exact signed bytes. */
function buildSignedEntity(signedEntity, armoredSig, micalg) {
  const b = boundary('sig');
  return (
    'Content-Type: multipart/signed; micalg=' + micalg + '; protocol="application/pgp-signature"; boundary="' + b + '"' + CRLF + CRLF +
    'This is an OpenPGP/MIME signed message (RFC 4880 and 3156)' + CRLF +
    '--' + b + CRLF +
    signedEntity + CRLF +
    '--' + b + CRLF +
    'Content-Type: application/pgp-signature; name="signature.asc"' + CRLF +
    'Content-Description: OpenPGP digital signature' + CRLF +
    'Content-Disposition: attachment; filename="signature.asc"' + CRLF + CRLF +
    toCRLF(armoredSig).trim() + CRLF + CRLF +
    '--' + b + '--'
  );
}

/* =================================================================
 * 3. PARSERS
 * ================================================================= */

/** Split an entity into { headerText, headers(Map lowercase->value), body }. */
function splitEntity(raw) {
  const s = Buffer.isBuffer(raw) ? raw.toString('binary') : raw; // binary keeps bytes 1:1
  let idx = s.indexOf('\r\n\r\n'), sepLen = 4;
  const lf = s.indexOf('\n\n');
  if (idx === -1 || (lf !== -1 && lf < idx)) { idx = lf; sepLen = 2; }
  if (idx === -1) return { headerText: s, headers: new Map(), body: '' };
  const headerText = s.slice(0, idx);
  const body = s.slice(idx + sepLen);
  const headers = new Map();
  headerText.replace(/\r?\n[ \t]+/g, ' ').split(/\r?\n/).forEach(line => {
    const c = line.indexOf(':');
    if (c > 0) {
      const k = line.slice(0, c).trim().toLowerCase();
      if (!headers.has(k)) headers.set(k, line.slice(c + 1).trim());
    }
  });
  return { headerText, headers, body };
}

/** Parse a Content-Type header into { type, params }. */
function parseContentType(v) {
  const p = mimeFuncs.parseHeaderValue(v || 'text/plain');
  return { type: (p.value || '').toLowerCase(), params: p.params || {} };
}

/**
 * Split a multipart body into its raw parts (binary strings).
 * Each part excludes the CRLF that precedes the next boundary, exactly
 * as RFC 3156 requires for signature verification.
 */
function splitMultipart(body, bnd) {
  const delim = '--' + bnd;
  const parts = [];
  // normalise: find each delimiter that starts a line
  const re = new RegExp('(^|\\r?\\n)' + escapeRe(delim) + '(--)?[ \\t]*(\\r?\\n|$)', 'g');
  let m, lastEnd = null;
  while ((m = re.exec(body)) !== null) {
    if (lastEnd !== null) parts.push(body.slice(lastEnd, m.index));
    if (m[2] === '--') { lastEnd = null; break; }
    lastEnd = m.index + m[0].length;
  }
  return parts;
}

function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

/** Decode a part body according to Content-Transfer-Encoding. Returns Buffer. */
function decodeBody(body, cte) {
  cte = (cte || '7bit').toLowerCase();
  if (cte === 'base64') return Buffer.from(body.replace(/[^A-Za-z0-9+/=]/g, ''), 'base64');
  if (cte === 'quoted-printable') {
    const s = body.replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
    return Buffer.from(s, 'binary');
  }
  return Buffer.from(body, 'binary');
}

module.exports = {
  CRLF, toCRLF, encHeader, formatAddress, parseAddressList,
  buildContentEntity, buildMessage, buildEncryptedEntity, buildSignedEntity,
  splitEntity, parseContentType, splitMultipart, decodeBody
};
