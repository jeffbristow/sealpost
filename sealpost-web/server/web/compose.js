/* =====================================================================
 * Sealpost Web — compose.js
 * ---------------------------------------------------------------------
 * Builds finished emails in the browser — the same way Sealpost on your
 * PC does (compose.js + mime.js there), so messages and drafts look
 * identical whichever one you used:
 *
 *   Encrypt ON           -> PGP/MIME multipart/encrypted (signed inside
 *                           when Sign is on). A copy is encrypted to your
 *                           own key so your Sent folder stays readable.
 *   Sign ON, Encrypt OFF -> PGP/MIME multipart/signed (detached signature)
 *   Both OFF             -> ordinary MIME message
 *   Hide subject         -> real subject travels inside the encryption
 *   Drafts               -> encrypted to your own key only
 *
 * Only finished, already-encrypted bytes are sent to your server.
 *
 * Sections:
 *   1. Low-level helpers (CRLF, base64, header encoding, addresses)
 *   2. MIME builders (content, outer message, signed, encrypted)
 *   3. Composing a message to send
 *   4. Building a draft
 * ===================================================================== */

/* =================================================================
 * 1. LOW-LEVEL HELPERS
 * ================================================================= */
const CRLF = '\r\n';
const te = new TextEncoder();
export const toCRLF = s => String(s).replace(/\r?\n/g, CRLF);

function randomHex(n) { return [...crypto.getRandomValues(new Uint8Array(n))].map(b => b.toString(16).padStart(2, '0')).join(''); }
const boundary = tag => '----=_Sealpost_' + tag + '_' + randomHex(12);

function b64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
const b64Wrap = bytes => b64(bytes).replace(/.{1,76}/g, '$&' + CRLF).replace(/\r\n$/, '');

const isPlainText = s => /^[\x20-\x7e]*$/.test(s);

/** RFC 2047 encoded words (UTF-8, base64), split so each stays short. */
function encodeWords(s) {
  const words = [];
  let chunk = '';
  for (const ch of s) {
    if (te.encode(chunk + ch).length > 45) { words.push(chunk); chunk = ''; }
    chunk += ch;
  }
  if (chunk) words.push(chunk);
  return words.map(w => '=?UTF-8?B?' + b64(te.encode(w)) + '?=').join(CRLF + ' ');
}

export function encHeader(v) {
  v = String(v || '').replace(/[\r\n]+/g, ' ');
  return isPlainText(v) ? v : encodeWords(v);
}

function formatAddress({ name, address }) {
  if (!name) return address;
  const n = isPlainText(name) ? '"' + name.replace(/["\\]/g, '\\$&') + '"' : encodeWords(name);
  return n + ' <' + address + '>';
}

/** 'Ann <ann@x.org>, "Doe, Bob" <bob@y.org>, c@z.org' -> [{ name, address }] */
export function parseAddressList(str) {
  const out = [];
  let cur = '', q = false, angle = false;
  const push = () => {
    const s = cur.trim(); cur = '';
    if (!s) return;
    const m = s.match(/^(.*?)<([^>]+)>\s*$/);
    let name = '', address = s;
    if (m) { name = m[1].trim().replace(/^"(.*)"$/, '$1').replace(/\\(.)/g, '$1'); address = m[2]; }
    address = address.trim().replace(/^mailto:/i, '');
    if (/^[^\s@<>",]+@[^\s@<>",]+\.[^\s@<>",]+$/.test(address)) out.push({ name, address });
  };
  for (const ch of String(str || '')) {
    if (ch === '"' && !angle) q = !q;
    if (ch === '<' && !q) angle = true;
    if (ch === '>' && !q) angle = false;
    if ((ch === ',' || ch === ';') && !q && !angle) { push(); continue; }
    cur += ch;
  }
  push();
  return out;
}

function encodeFilename(name) {
  return isPlainText(name) ? 'filename="' + name.replace(/"/g, '') + '"' : "filename*=UTF-8''" + encodeURIComponent(name);
}

const MIME_TYPES = {
  pdf: 'application/pdf', txt: 'text/plain', csv: 'text/csv', html: 'text/html', htm: 'text/html', json: 'application/json',
  png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp', svg: 'image/svg+xml', heic: 'image/heic',
  zip: 'application/zip', '7z': 'application/x-7z-compressed', doc: 'application/msword', docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xls: 'application/vnd.ms-excel', xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  ppt: 'application/vnd.ms-powerpoint', pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  mp3: 'audio/mpeg', mp4: 'video/mp4', mov: 'video/quicktime', asc: 'application/pgp-keys', gpg: 'application/octet-stream', pgp: 'application/octet-stream', eml: 'message/rfc822'
};
export const detectType = name => MIME_TYPES[(String(name).split('.').pop() || '').toLowerCase()] || 'application/octet-stream';

/* =================================================================
 * 2. MIME BUILDERS
 * ================================================================= */
/** text (+ html) (+ attachments) (+ protected headers) -> entity string */
function buildContentEntity({ text, html, attachments = [], protectedHeaders = null }) {
  const textPart =
    'Content-Type: text/plain; charset=utf-8' + CRLF +
    'Content-Transfer-Encoding: base64' + CRLF + CRLF +
    b64Wrap(te.encode(toCRLF(text || '')));
  let body = textPart;
  if (html) {
    const b = boundary('alt');
    body =
      'Content-Type: multipart/alternative; boundary="' + b + '"' + CRLF + CRLF +
      '--' + b + CRLF + textPart + CRLF +
      '--' + b + CRLF +
      'Content-Type: text/html; charset=utf-8' + CRLF +
      'Content-Transfer-Encoding: base64' + CRLF + CRLF +
      b64Wrap(te.encode(html)) + CRLF +
      '--' + b + '--';
  }
  const phLines = protectedHeaders ? Object.entries(protectedHeaders).map(([k, v]) => k + ': ' + encHeader(v)).join(CRLF) + CRLF : '';
  if (!attachments.length && !protectedHeaders) return body;

  const b = boundary('mix');
  let out =
    'Content-Type: multipart/mixed; boundary="' + b + '"' + (protectedHeaders ? '; protected-headers="v1"' : '') + CRLF +
    phLines + CRLF +
    '--' + b + CRLF + body + CRLF;
  for (const a of attachments) {
    const ct = a.contentType || detectType(a.filename);
    out +=
      '--' + b + CRLF +
      'Content-Type: ' + ct + '; name="' + (isPlainText(a.filename) ? a.filename.replace(/"/g, '') : encHeader(a.filename)) + '"' + CRLF +
      'Content-Disposition: attachment; ' + encodeFilename(a.filename) + CRLF +
      'Content-Transfer-Encoding: base64' + CRLF + CRLF +
      b64Wrap(a.bytes) + CRLF;
  }
  return out + '--' + b + '--';
}

function buildMessage({ from, to = [], cc = [], bcc = [], subject, inReplyTo, references, entity, includeBcc = false }) {
  const domain = (from.address.split('@')[1] || 'localhost').replace(/[^a-z0-9.-]/gi, '');
  const messageId = '<' + crypto.randomUUID() + '@' + domain + '>';
  const h = ['From: ' + formatAddress(from)];
  if (to.length) h.push('To: ' + to.map(formatAddress).join(', '));
  if (cc.length) h.push('Cc: ' + cc.map(formatAddress).join(', '));
  if (includeBcc && bcc.length) h.push('Bcc: ' + bcc.map(formatAddress).join(', '));
  h.push('Subject: ' + encHeader(subject || ''));
  h.push('Date: ' + new Date().toUTCString().replace('GMT', '+0000'));
  h.push('Message-ID: ' + messageId);
  if (inReplyTo) h.push('In-Reply-To: ' + inReplyTo);
  if (references) h.push('References: ' + references);
  h.push('MIME-Version: 1.0');
  h.push('X-Mailer: Sealpost Web');
  return { raw: h.join(CRLF) + CRLF + toCRLF(entity) + CRLF, messageId };
}

function buildEncryptedEntity(armored) {
  const b = boundary('enc');
  return 'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="' + b + '"' + CRLF + CRLF +
    'This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)' + CRLF +
    '--' + b + CRLF + 'Content-Type: application/pgp-encrypted' + CRLF + 'Content-Description: PGP/MIME version identification' + CRLF + CRLF +
    'Version: 1' + CRLF + CRLF +
    '--' + b + CRLF + 'Content-Type: application/octet-stream; name="encrypted.asc"' + CRLF + 'Content-Description: OpenPGP encrypted message' + CRLF +
    'Content-Disposition: inline; filename="encrypted.asc"' + CRLF + CRLF +
    toCRLF(armored).trim() + CRLF + CRLF + '--' + b + '--';
}

function buildSignedEntity(signedEntity, armoredSig, micalg) {
  const b = boundary('sig');
  return 'Content-Type: multipart/signed; micalg=' + micalg + '; protocol="application/pgp-signature"; boundary="' + b + '"' + CRLF + CRLF +
    'This is an OpenPGP/MIME signed message (RFC 4880 and 3156)' + CRLF +
    '--' + b + CRLF + signedEntity + CRLF +
    '--' + b + CRLF + 'Content-Type: application/pgp-signature; name="signature.asc"' + CRLF + 'Content-Description: OpenPGP digital signature' + CRLF +
    'Content-Disposition: attachment; filename="signature.asc"' + CRLF + CRLF +
    toCRLF(armoredSig).trim() + CRLF + CRLF + '--' + b + '--';
}

/** Rich text: wrap the editor's HTML in a minimal document. */
function wrapHtml(fragment) {
  return '<!doctype html><html><head><meta charset="utf-8"></head><body style="font-family:Segoe UI,Arial,sans-serif;font-size:14px">' + fragment + '</body></html>';
}

/** Plain-text version of rich text (for recipients whose program shows text only). */
export function htmlToPlain(html) {
  const doc = new DOMParser().parseFromString(`<div>${html}</div>`, 'text/html');
  const root = doc.body.firstChild;
  root.querySelectorAll('br').forEach(n => n.replaceWith('\n'));
  root.querySelectorAll('p,div,li,h1,h2,h3,h4,tr,blockquote').forEach(n => n.append('\n'));
  root.querySelectorAll('a[href]').forEach(a => { if (a.textContent.trim() !== a.getAttribute('href')) a.append(` (${a.getAttribute('href')})`); });
  root.querySelectorAll('li').forEach(li => li.prepend('• '));
  return root.textContent.replace(/\n{3,}/g, '\n\n').trim();
}

/* =================================================================
 * 3. COMPOSE A MESSAGE TO SEND
 *    draft: { to, cc, bcc, subject, text, html, encrypt, sign,
 *             hideSubject, attachPublicKey, attachments:[{filename,
 *             contentType, bytes}], inReplyTo, references }
 *    -> { raw (string, ASCII), messageId, envelope: { from, to[] } }
 * ================================================================= */
/* =================================================================
 * 2b. "SEND AS" (1.7.0) — same rules as Sealpost on your PC:
 *     the From address is the account's own or one of its "Send as"
 *     addresses (account.aliases); anything else falls back to the
 *     account. An alias without its own key signs with the account's.
 * ================================================================= */
export function senderFor(account, fromAddress) {
  const want = String(fromAddress || '').trim().toLowerCase();
  const alias = want && want !== String(account.email).toLowerCase()
    ? (account.aliases || []).find(a => String(a.email).toLowerCase() === want) : null;
  return alias
    ? { name: alias.name || account.name || '', address: alias.email, alias: true }
    : { name: account.name || '', address: account.email, alias: false };
}
async function myKeyFor(keyring, account, sender) {
  return (await keyring.findSecretFor(sender.address)) || (sender.alias ? await keyring.findSecretFor(account.email) : null);
}

export async function composeMessage(keyring, account, draft) {
  const sender = senderFor(account, draft.fromAddress);
  const from = { name: sender.name, address: sender.address };
  const to = parseAddressList(draft.to), cc = parseAddressList(draft.cc), bcc = parseAddressList(draft.bcc);
  const allRecipients = [...new Set([...to, ...cc, ...bcc].map(a => a.address.toLowerCase()))];
  if (!allRecipients.length) throw new Error('Add at least one recipient');

  const attachments = [...(draft.attachments || [])];
  const myFp = (draft.sign || draft.encrypt || draft.attachPublicKey) ? await myKeyFor(keyring, account, sender) : null;
  if (draft.sign && !myFp) throw new Error('You have no usable private key for ' + sender.address + '. Create or import one under Keys, or turn off Sign.');
  if (draft.attachPublicKey && myFp) {
    attachments.push({ filename: 'OpenPGP_0x' + myFp.slice(-16) + '.asc', contentType: 'application/pgp-keys', bytes: te.encode(keyring.publicKeys.get(myFp).armor()) });
  }

  const html = draft.html ? wrapHtml(draft.html) : null;
  const text = draft.text || (draft.html ? htmlToPlain(draft.html) : '');
  const subject = draft.subject || '';
  let entity, outerSubject = subject;

  if (draft.encrypt) {
    const inner = toCRLF(buildContentEntity({ text, html, attachments, protectedHeaders: draft.hideSubject ? { Subject: subject } : null }));
    const armored = await keyring.encrypt({ data: te.encode(inner), recipients: allRecipients, signerFp: draft.sign ? myFp : null, encryptToSelfFp: myFp });
    entity = buildEncryptedEntity(armored);
    if (draft.hideSubject) outerSubject = '...';
  } else if (draft.sign) {
    const inner = toCRLF(buildContentEntity({ text, html, attachments }));
    const sig = await keyring.signDetached({ data: te.encode(inner), signerFp: myFp });
    entity = buildSignedEntity(inner, sig, await keyring.micalgOf(sig));
  } else {
    entity = buildContentEntity({ text, html, attachments });
  }

  const built = buildMessage({ from, to, cc, bcc, subject: outerSubject, inReplyTo: draft.inReplyTo, references: draft.references, entity });
  return { raw: built.raw, messageId: built.messageId, envelope: { from: sender.address, to: allRecipients } };
}

/* =================================================================
 * 4. BUILD A DRAFT
 *    Everything — recipients, subject, body, attachments and the
 *    composer settings — is encrypted to YOUR OWN key, so the mail
 *    server stores it but can't read it. Same format as Sealpost on
 *    your PC, so a draft started here can be finished there.
 * ================================================================= */
export async function buildDraft(keyring, account, draft) {
  const sender = senderFor(account, draft.fromAddress);   // 1.7.0
  const from = { name: sender.name, address: sender.address };
  const html = draft.html ? wrapHtml(draft.html) : null;
  const text = draft.text || (draft.html ? htmlToPlain(draft.html) : '');
  const meta = b64(te.encode(JSON.stringify({
    v: 1, format: draft.html ? 'rich' : 'plain',
    encrypt: !!draft.encrypt, sign: !!draft.sign, hideSubject: !!draft.hideSubject, attachPublicKey: !!draft.attachPublicKey,
    inReplyTo: draft.inReplyTo || null, references: draft.references || null,
    replyToUid: draft.replyToUid || null, replyFolder: draft.replyFolder || null,
    fromAddress: sender.alias ? sender.address : null       // 1.7.0
  })));
  const headers = { To: draft.to || '', Cc: draft.cc || '', Bcc: draft.bcc || '', Subject: draft.subject || '', 'X-Sealpost-Draft': meta };
  const myFp = await myKeyFor(keyring, account, sender);
  let entity, subject, encrypted = false;
  if (myFp) {
    const inner = toCRLF(buildContentEntity({ text, html, attachments: draft.attachments || [], protectedHeaders: headers }));
    const armored = await keyring.encrypt({ data: te.encode(inner), recipients: [], encryptToSelfFp: myFp });
    entity = buildEncryptedEntity(armored);
    subject = 'Encrypted draft';
    encrypted = true;
  } else {
    const { To, Cc, Subject, ...rest } = headers;
    entity = buildContentEntity({ text, html, attachments: draft.attachments || [], protectedHeaders: rest });
    subject = draft.subject || '';
  }
  const built = buildMessage({ from, to: encrypted ? [] : parseAddressList(draft.to), cc: encrypted ? [] : parseAddressList(draft.cc), subject, entity });
  return { raw: built.raw, messageId: built.messageId, encrypted };
}
