#!/usr/bin/env node
/* =====================================================================
 * Sealpost — sealpost-web/tools/release-server.js   (1.10.0)
 * ---------------------------------------------------------------------
 * Packages and signs a Sealpost Server release so one-click updates
 * (lib.php section 8) accept it.
 *
 *   node sealpost-web/tools/release-server.js [--note "what's new"] [--key path/to/key.pem]
 *
 * Writes into sealpost-web/dist/:
 *   Sealpost-Web-Server-<ver>.zip       git archive of the COMMITTED
 *                                       sealpost-web/server (so config.php,
 *                                       which git ignores, can never be in it)
 *   Sealpost-Web-Server-<ver>.zip.sig   the signature servers check
 * and updates server-update.json (repo root) — what servers ask for.
 *
 * Publish in this order (servers must never be told about a file that
 * isn't downloadable yet):
 *   1. gh release create server-v<ver> --latest=false … the zip + .sig
 *   2. commit + push server-update.json
 *
 * The private key (default ~/.sealpost/update-signing-key.pem) must stay
 * offline: never in the repository, a package, or on a web server.
 *
 * Sections:
 *   1. Arguments + checks (clean tree, version)
 *   2. Package
 *   3. Sign + self-check
 *   4. server-update.json
 * ===================================================================== */
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const REPO = 'jeffbristow/sealpost';
const root = path.join(__dirname, '..', '..');
const git = (...a) => execFileSync('git', a, { cwd: root, maxBuffer: 1 << 26 });
const die = m => { console.error(m); process.exit(1); };

/* ---------- 1. arguments + checks ---------- */
const arg = n => { const i = process.argv.indexOf('--' + n); return i > 0 ? process.argv[i + 1] : null; };
const keyFile = arg('key') || path.join(os.homedir(), '.sealpost', 'update-signing-key.pem');
const note = (arg('note') || '').slice(0, 300);
if (!fs.existsSync(keyFile)) die('Signing key not found: ' + keyFile);

const dirty = git('status', '--porcelain', '--', 'sealpost-web/server').toString().trim();
if (dirty) die('Commit the changes in sealpost-web/server first — the package is made from the committed files:\n' + dirty);
const lib = git('show', 'HEAD:sealpost-web/server/lib.php').toString();
const version = (/SEALPOST_SERVER_VERSION\s*=\s*'(\d+\.\d+\.\d+)'/.exec(lib) || [])[1];
if (!version) die('No SEALPOST_SERVER_VERSION in lib.php');
const pub64 = (/UPDATE_PUBKEY\s*=\s*'([A-Za-z0-9+/=]+)'/.exec(lib) || [])[1];
if (!pub64) die('No UPDATE_PUBKEY in lib.php');
const stamped = git('show', 'HEAD:sealpost-web/server/sw.js').toString().includes(`sealpost-shell-${version}'`);
if (!stamped) die(`sw.js isn't stamped with ${version} — run sealpost-web/devtest/stamp.sh and commit first.`);

/* ---------- 2. package ---------- */
const out = path.join(root, 'sealpost-web', 'dist');
fs.mkdirSync(out, { recursive: true });
const name = `Sealpost-Web-Server-${version}.zip`;
const zip = path.join(out, name);
git('archive', '--format=zip', '--prefix=sealpost-server/', '-o', zip, 'HEAD:sealpost-web/server');
const data = fs.readFileSync(zip);
const sha256 = crypto.createHash('sha256').update(data).digest('hex');

/* ---------- 3. sign + self-check ---------- */
const text = `sealpost-server-update-v1|${version}|${sha256}`;
const key = crypto.createPrivateKey(fs.readFileSync(keyFile));
const sig = crypto.sign(null, Buffer.from(text), key);
const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');   // Ed25519 SubjectPublicKeyInfo header
const builtIn = crypto.createPublicKey({ key: Buffer.concat([spkiPrefix, Buffer.from(pub64, 'base64')]), format: 'der', type: 'spki' });
if (!crypto.verify(null, Buffer.from(text), builtIn, sig)) die('This key is NOT the one in lib.php (UPDATE_PUBKEY) — servers would refuse the package.');
fs.writeFileSync(zip + '.sig', JSON.stringify({ v: 1, kind: 'sealpost-server', file: name, version, sha256, size: data.length, sig: sig.toString('base64') }, null, 2) + '\n');

/* ---------- 4. server-update.json ---------- */
const info = {
  version,
  url: `https://github.com/${REPO}/releases/download/server-v${version}/${name}`,
  sha256,
  size: Math.round(data.length / 1024) + ' KB',
  note
};
fs.writeFileSync(path.join(root, 'server-update.json'), JSON.stringify(info, null, 2) + '\n');

console.log(`Sealpost Server ${version}
  ${zip}
  ${zip}.sig
  sha256 ${sha256}
  server-update.json updated

Publish:
  gh release create server-v${version} --latest=false --title "Sealpost Server ${version}" "${zip}" "${zip}.sig"
  git add server-update.json && git commit -m "Sealpost Server ${version}" && git push`);
