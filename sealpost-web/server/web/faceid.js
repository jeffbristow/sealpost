/* =====================================================================
 * Sealpost Web — faceid.js  (Face ID unlock, added 1.6.0)
 * ---------------------------------------------------------------------
 * Lets the iPhone app open with Face ID instead of typing the PIN.
 * Uses a passkey (WebAuthn) saved in your iCloud Keychain, with its
 * "PRF" extension: after a successful Face ID scan the passkey hands
 * this page a secret key that never exists anywhere else. That key
 * encrypts your PIN on this phone; Face ID decrypts it and Sealpost then
 * unlocks exactly as if you had typed the PIN (the server still checks
 * it, and still counts wrong tries).
 *
 * Needs iOS 18 or newer (Safari's passkey PRF support). On other
 * devices it works wherever the browser supports passkeys with PRF
 * (Windows Hello, Android, Touch ID on a Mac).
 *
 * Sections:
 *   1. Helpers (base64url, names)
 *   2. Is it available here?
 *   3. Turn on: create (or reuse) the passkey, encrypt the PIN
 *   4. Unlock: Face ID -> PIN
 * ===================================================================== */

import { seal, unseal } from './vault.js?v=1.11.0';

/* =================================================================
 * 1. HELPERS
 * ================================================================= */
const te = new TextEncoder(), td = new TextDecoder();
const b64u = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), c => c.charCodeAt(0));
const PASSKEY_KEY = 'sealpost-passkey';   // this phone's passkey account handle (see enableFace)

const isApple = () => /iPhone|iPad|iPod|Macintosh/.test(navigator.userAgent);
/** What to call it on this device. */
export const faceName = () => /iPhone|iPad|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1) ? 'Face ID'
  : /Windows/.test(navigator.userAgent) ? 'Windows Hello' : isApple() ? 'Touch ID' : 'fingerprint / face unlock';

function storedPasskey(username) {
  try { const p = JSON.parse(localStorage.getItem(PASSKEY_KEY) || 'null'); return p && p.username === username ? p : null; } catch { return null; }
}

/** The key that encrypts the PIN, from the passkey's PRF output. */
async function prfKey(prfBytes) {
  const hk = await crypto.subtle.importKey('raw', prfBytes, 'HKDF', false, ['deriveBits']);
  const raw = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: te.encode('sealpost-faceid') }, hk, 256);
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

function friendly(e) {
  if (e && e.name === 'NotAllowedError') return Object.assign(new Error(`${faceName()} was cancelled.`), { code: 'CANCELLED' });
  if (e && e.name === 'SecurityError') return new Error(`${faceName()} needs this page to be opened through its https:// address.`);
  return e instanceof Error ? e : new Error(String(e));
}

/* =================================================================
 * 2. AVAILABLE?
 * ================================================================= */
export async function faceSupported() {
  try {
    if (!window.PublicKeyCredential || !window.isSecureContext) return false;
    if (PublicKeyCredential.getClientCapabilities) {
      const caps = await PublicKeyCredential.getClientCapabilities();
      if (caps && caps['extension:prf'] === false) return false;
    }
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch { return false; }
}

/* =================================================================
 * 3. TURN ON — returns { credId, salt, wrapped } to keep on this phone
 * ================================================================= */
async function getPrf(credId, salt) {
  const cred = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId: location.hostname,
      allowCredentials: [{ type: 'public-key', id: unb64u(credId) }],
      userVerification: 'required',
      timeout: 60000,
      extensions: { prf: { eval: { first: salt } } }
    }
  });
  const prf = cred && cred.getClientExtensionResults().prf;
  if (!prf || !prf.results || !prf.results.first) throw new Error(`This device's ${faceName()} can't provide the key Sealpost needs (iOS 18 or newer is required on iPhone).`);
  return new Uint8Array(prf.results.first);
}

export async function enableFace(pin, username) {
  const salt = crypto.getRandomValues(new Uint8Array(32));
  // the same account handle every time: turning Face ID off and on again
  // replaces this phone's Sealpost passkey instead of piling up new ones
  const old = storedPasskey(username);
  const handle = old && old.handle ? unb64u(old.handle) : crypto.getRandomValues(new Uint8Array(16));
  let credId, prfOut;
  try {
    const cred = await navigator.credentials.create({
      publicKey: {
        rp: { name: 'Sealpost', id: location.hostname },
        user: { id: handle, name: `${username} (Sealpost)`, displayName: `Sealpost — ${username}` },
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' },
        timeout: 60000,
        attestation: 'none',
        extensions: { prf: { eval: { first: salt } } }
      }
    });
    const prf = cred.getClientExtensionResults().prf;
    if (!prf || prf.enabled === false) throw new Error(`This device's ${faceName()} doesn't support what Sealpost needs (iOS 18 or newer is required on iPhone).`);
    credId = b64u(cred.rawId);
    try { localStorage.setItem(PASSKEY_KEY, JSON.stringify({ username, handle: b64u(handle) })); } catch { /* ignore */ }
    // some devices return the key right away; others need one more scan
    prfOut = prf.results && prf.results.first ? new Uint8Array(prf.results.first) : await getPrf(credId, salt);
  } catch (e) { throw friendly(e); }
  const wrapped = await seal(await prfKey(prfOut), te.encode(String(pin)), 'sealpost-faceid-pin');
  return { credId, salt: b64u(salt), wrapped };
}

/* =================================================================
 * 4. UNLOCK — Face ID scan -> the PIN (then unlocked as usual)
 * ================================================================= */
export async function pinFromFace(face) {
  let prfOut;
  try { prfOut = await getPrf(face.credId, unb64u(face.salt)); } catch (e) { throw friendly(e); }
  try { return td.decode(await unseal(await prfKey(prfOut), face.wrapped, 'sealpost-faceid-pin')); }
  catch { throw Object.assign(new Error(`${faceName()} data on this phone doesn't match any more. Use your PIN, then turn ${faceName()} on again in Settings.`), { code: 'FACE_STALE' }); }
}
