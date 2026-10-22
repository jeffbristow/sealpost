/* =====================================================================
 * Sealpost — compose.js
 * ---------------------------------------------------------------------
 * Turns what you typed in the composer into a finished raw email,
 * applying PGP signing and/or encryption.
 *
 *   Encrypt ON           -> PGP/MIME multipart/encrypted (signed inside
 *                           when Sign is also on). A copy is encrypted to
 *                           your own key so your Sent folder stays readable.
 *   Sign ON, Encrypt OFF -> PGP/MIME multipart/signed (detached sig)
 *   Both OFF             -> ordinary MIME message
 *
 * "Hide subject" moves the real subject inside the encryption
 * (protected headers) — Thunderbird, Proton and Mailvelope display it.
 * ===================================================================== */

const fs = require('fs');
const path = require('path');
const openpgp = require('openpgp');
const mime = require('./mime');
const { convert: htmlToText } = require('html-to-text');

/* ---------- Rich text helpers (1.1.0) ---------- */
function htmlToPlain(html) {
  try { return htmlToText(html, { wordwrap: 76, selectors: [{ selector: 'a', options: { hideLinkHrefIfSameAsText: true } }, { selector: 'img', format: 'skip' }] }); }
  catch { return ''; }
}

// Full HTML document around the editor's content, with sensible defaults
function wrapHtml(fragment) {
  return '<!DOCTYPE html><html><head><meta charset="utf-8"></head>' +
    '<body style="font-family: Segoe UI, Arial, sans-serif; font-size: 14px; line-height: 1.45;">' +
    fragment + '</body></html>';
}

/* ---------- Gather attachments (paths on disk, or base64 from a reopened draft) ---------- */
function loadAttachments(list) {
  const out = [];
  for (const a of list || []) {
    if (a.path) out.push({ filename: path.basename(a.path), content: fs.readFileSync(a.path) });
    else if (a.content) out.push({ filename: a.filename, content: Buffer.from(a.content, 'base64'), contentType: a.contentType });
  }
  return out;
}

/* ---------- Section: "Send as" (1.9.0) ----------
 * The From address can be the account's own address or one of its
 * "Send as" addresses (account.aliases). Anything else falls back to the
 * account's own address — Sealpost never sends as an address you haven't
 * set up. */
function senderFor(account, fromAddress) {
  const want = String(fromAddress || '').trim().toLowerCase();
  const alias = want && want !== String(account.email).toLowerCase()
    ? (account.aliases || []).find(a => String(a.email).toLowerCase() === want) : null;
  return alias
    ? { name: alias.name || account.name || '', address: alias.email, alias: true }
    : { name: account.name || '', address: account.email, alias: false };
}

/** My signing key for this From address: its own key, else the account's. */
async function myKeyFor(pgp, account, sender) {
  return (await pgp.findSecretFor(sender.address)) || (sender.alias ? await pgp.findSecretFor(account.email) : null);
}

async function composeMessage(pgp, account, draft) {
  const sender = senderFor(account, draft.fromAddress);
  const from = { name: sender.name, address: sender.address };
  const to = mime.parseAddressList(draft.to);
  const cc = mime.parseAddressList(draft.cc);
  const bcc = mime.parseAddressList(draft.bcc);
  const allRecipients = [...to, ...cc, ...bcc].map(a => a.address.toLowerCase());
  if (!allRecipients.length) throw new Error('Add at least one recipient');

  /* ---------- Section: gather attachments from disk ---------- */
  const attachments = loadAttachments(draft.attachments);

  /* ---------- Section: find my own key ---------- */
  const myFp = (draft.sign || draft.encrypt || draft.attachPublicKey) ? await myKeyFor(pgp, account, sender) : null;
  if ((draft.sign || draft.encrypt) && !myFp && draft.sign) {
    throw new Error('You have no usable private key for ' + sender.address + '. Create or import one in the Keys view, or turn off Sign.');
  }

  if (draft.attachPublicKey && myFp) {
    attachments.push({
      filename: 'OpenPGP_0x' + myFp.slice(-16) + '.asc',
      contentType: 'application/pgp-keys',
      content: Buffer.from(pgp.exportPublic(myFp), 'utf8')
    });
  }

  // Rich text (1.1.0): HTML from the editor + a plain-text version for
  // recipients whose mail program shows text only.
  const html = draft.html ? wrapHtml(draft.html) : null;
  let text = draft.text || (draft.html ? htmlToPlain(draft.html) : '');
  const subject = draft.subject || '';

  /* ---------- Section: build the body according to PGP mode ---------- */
  let entity;
  let outerSubject = subject;

  if (draft.encrypt) {
    const inner = mime.toCRLF(mime.buildContentEntity({
      text, html, attachments,
      protectedHeaders: draft.hideSubject ? { Subject: subject } : null
    }));
    const armored = await pgp.encrypt({
      data: Buffer.from(inner, 'binary'),
      recipients: allRecipients,
      signerFp: draft.sign ? myFp : null,
      encryptToSelfFp: myFp
    });
    entity = mime.buildEncryptedEntity(armored);
    if (draft.hideSubject) outerSubject = '...';
  } else if (draft.sign) {
    const inner = mime.toCRLF(mime.buildContentEntity({ text, html, attachments }));
    const sig = await pgp.signDetached({ data: Buffer.from(inner, 'binary'), signerFp: myFp });
    entity = mime.buildSignedEntity(inner, sig, await micalgOf(sig));
  } else {
    entity = mime.buildContentEntity({ text, html, attachments });
  }

  const built = mime.buildMessage({
    from, to, cc, bcc,
    subject: outerSubject,
    inReplyTo: draft.inReplyTo,
    references: draft.references,
    entity
  });

  return {
    raw: Buffer.from(built.raw, 'binary'),
    messageId: built.messageId,
    envelope: { from: sender.address, to: allRecipients }   // 1.9.0: the "Send as" address when one is chosen
  };
}

/* =====================================================================
 * Drafts (1.1.0)
 * The whole draft — recipients, subject, body, attachments and the
 * composer settings — is encrypted to YOUR OWN key only, so the mail
 * server stores it but can't read it. Only the subject "Encrypted draft"
 * is visible on the server. Without a key of your own the draft is saved
 * unencrypted (the composer tells you).
 * ===================================================================== */
async function buildDraft(pgp, account, draft) {
  const sender = senderFor(account, draft.fromAddress);   // 1.9.0
  const from = { name: sender.name, address: sender.address };
  const attachments = loadAttachments(draft.attachments);
  const html = draft.html ? wrapHtml(draft.html) : null;
  const text = draft.text || (draft.html ? htmlToPlain(draft.html) : '');
  const meta = Buffer.from(JSON.stringify({
    v: 1, format: draft.html ? 'rich' : 'plain',
    encrypt: !!draft.encrypt, sign: !!draft.sign, hideSubject: !!draft.hideSubject, attachPublicKey: !!draft.attachPublicKey,
    inReplyTo: draft.inReplyTo || null, references: draft.references || null,
    replyToUid: draft.replyToUid || null, replyFolder: draft.replyFolder || null,
    fromAddress: sender.alias ? sender.address : null       // 1.9.0: reopened with the same "Send as" address
  })).toString('base64');
  const headers = { To: draft.to || '', Cc: draft.cc || '', Bcc: draft.bcc || '', Subject: draft.subject || '', 'X-Sealpost-Draft': meta };

  const myFp = await myKeyFor(pgp, account, sender);
  let entity, subject, encrypted = false;
  if (myFp) {
    const inner = mime.toCRLF(mime.buildContentEntity({ text, html, attachments, protectedHeaders: headers }));
    const armored = await pgp.encrypt({ data: Buffer.from(inner, 'binary'), recipients: [], encryptToSelfFp: myFp });
    entity = mime.buildEncryptedEntity(armored);
    subject = 'Encrypted draft';
    encrypted = true;
  } else {
    // unencrypted: To/Cc/Subject go in the normal message headers (not repeated)
    const { To, Cc, Subject, ...rest } = headers;
    entity = mime.buildContentEntity({ text, html, attachments, protectedHeaders: rest });
    subject = draft.subject || '';
  }
  const built = mime.buildMessage({
    from,
    to: encrypted ? [] : mime.parseAddressList(draft.to),
    cc: encrypted ? [] : mime.parseAddressList(draft.cc),
    subject, entity
  });
  return { raw: Buffer.from(built.raw, 'binary'), messageId: built.messageId, encrypted };
}

// micalg parameter must name the hash actually used in the signature
async function micalgOf(armoredSig) {
  try {
    const sig = await openpgp.readSignature({ armoredSignature: armoredSig });
    const n = sig.packets[0].hashAlgorithm;
    return 'pgp-' + openpgp.enums.read(openpgp.enums.hash, n).toLowerCase();
  } catch {
    return 'pgp-sha256';
  }
}

module.exports = { composeMessage, buildDraft, htmlToPlain, senderFor };
