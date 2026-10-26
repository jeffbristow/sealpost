/* =====================================================================
 * Sealpost — addy.js   (added 1.13.0)
 * ---------------------------------------------------------------------
 * addy.io reply / "send from" addresses.
 *
 * To write to someone through an addy.io alias, the To address carries
 * the real recipient inside it:
 *     <alias>+<recipient, with @ written as =>@<alias domain>
 *     shop+sam=example.org@example.com    →   sam@example.org
 *     shop+hello+news=example.com@me.addy.io → hello+news@example.com
 * addy.io sends the message on to the real address, so a PGP message
 * must be encrypted to the REAL recipient's key. With "I use addy.io"
 * on (settings.addyRecipients), every key lookup — choosing the key to
 * encrypt to, the composer's key chips, contact-assigned keys and the
 * online search — uses the real address. The To field is left alone.
 *
 * Only addresses on an addy.io domain are read this way: addy.io's own
 * domains (and their subdomains, e.g. you.addy.io), the domains of your
 * "Send as" addresses, and any custom domains listed in
 * settings.addyDomains. Sealpost Web has the same rules (web/addy.js).
 *
 * Sections:
 *   1. addy.io's own domains
 *   2. Reading an addy.io address
 *   3. Settings -> options
 * ===================================================================== */

/* =================================================================
 * 1. ADDY.IO'S OWN DOMAINS (subdomains count too)
 * ================================================================= */
const ADDY_DOMAINS = ['addy.io', 'anonaddy.com', 'anonaddy.me', 'addymail.com', 'mailer.me'];

const norm = e => String(e || '').trim().toLowerCase();

/** "example.com, @example.org\nfoo.net" -> ['example.com', 'example.org', 'foo.net'] */
function cleanDomains(list) {
  const items = Array.isArray(list) ? list : String(list || '').split(/[\s,;]+/);
  const out = [];
  for (const x of items) {
    const d = norm(x).replace(/^@+/, '').replace(/\.+$/, '');
    if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d) && !out.includes(d)) out.push(d);
  }
  return out;
}

const onDomain = (domain, list) => list.some(d => domain === d || domain.endsWith('.' + d));

/* =================================================================
 * 2. READING AN ADDY.IO ADDRESS
 * ================================================================= */
/**
 * The real recipient inside an addy.io address, or null when it isn't one.
 * Everything after the FIRST "+" is the recipient; its LAST "=" stands
 * for "@" (a recipient's own "+tag" stays: first+a+b=x.com -> a+b@x.com).
 */
function decodeAddy(email, domains = ADDY_DOMAINS) {
  const e = norm(email);
  const at = e.lastIndexOf('@');
  if (at < 1) return null;
  const local = e.slice(0, at), domain = e.slice(at + 1);
  if (!onDomain(domain, domains)) return null;
  const plus = local.indexOf('+');
  if (plus < 1) return null;
  const rest = local.slice(plus + 1);
  const eq = rest.lastIndexOf('=');
  if (eq < 1) return null;
  const real = rest.slice(0, eq) + '@' + rest.slice(eq + 1);
  return /^[^\s@<>]+@[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(real) ? real : null;
}

/* =================================================================
 * 3. SETTINGS -> OPTIONS
 * ================================================================= */
/** The domains to read: addy.io's own + "Send as" domains + settings.addyDomains. */
function addyDomains(settings = {}, accounts = []) {
  const own = [];
  for (const a of accounts || []) for (const al of a.aliases || []) {
    const d = norm(al.email).split('@')[1];
    if (d) own.push(d);
  }
  return cleanDomains([...ADDY_DOMAINS, ...own, ...cleanDomains(settings.addyDomains)]);
}

/**
 * email -> the address to use for keys: the real recipient when "I use
 * addy.io" is on and this is an addy.io address, otherwise the address itself.
 */
function keyAddressFn(settings = {}, accounts = []) {
  if (!settings.addyRecipients) return e => norm(e);
  const domains = addyDomains(settings, accounts);
  return e => decodeAddy(e, domains) || norm(e);
}

module.exports = { ADDY_DOMAINS, cleanDomains, decodeAddy, addyDomains, keyAddressFn };
