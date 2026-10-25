# CLAUDE.md

Guidance for Claude Code when working on Sealpost. Read this first.

## The purpose (everything else serves this)

Sealpost is **one PGP mail setup that follows you across devices**: an IMAP
client with an excellent OpenPGP implementation, plus a web interface, where
**settings, accounts, contacts and PGP keys stay in sync between every client**.
A user should be able to jump between their Windows PC, Mac, Linux machine,
browser and iPhone with minimal effort and still encrypt, decrypt, sign and
verify everywhere.

So for every client that exists or gets added (Windows, macOS 12/13+, Linux,
Sealpost Web, the iPhone home-screen app, anything future):
- **It joins the same vault.** It speaks the vault protocol exactly
  (`sync.js` ⇄ `web/vault.js` ⇄ `api.php`): same key derivation, same
  `v1.` AES-GCM items with the item id as AAD, same item envelope
  `{ v, id, type, updated, device, data }`, same item types. No
  client-only formats.
- **Everything that makes PGP work syncs**: keys (secret keys still under
  their own passphrase), passphrases marked "remember on all my devices",
  contacts with their pinned keys and encrypt/sign rules, accounts, settings.
  Mail written or drafted on one client must open on every other (shared
  PGP/MIME + draft formats — see rule 1 below).
- **Device-specific things stay out of the vault**: only `LOCAL_SETTINGS`
  (app lock, offline cache, backup date, Windows shortcut icon, sync state)
  and each device's own secure storage (DPAPI / Keychain / Linux keyring).
  Never put an OS-specific value (a file path, a Windows-only option) in a
  synced item — another OS will receive it.
- **`sealpost/test/clients-test.js` must pass** (desktop and web open each
  other's vault items; same per-device settings list). A new client gets
  added to it. Features that need a minimum version of another client say so
  (e.g. "syncs with Sealpost Web 1.8.0+").
- When in doubt, ask "can a user who switches devices right now still
  decrypt and keep working?" If not, it isn't done.

## What Sealpost is

A PGP email system with two halves that share one encrypted "vault":

| Part | Folder | Tech | Current version |
|------|--------|------|-----------------|
| **Sealpost** — desktop IMAP/SMTP client (Windows 11, macOS 12+, Linux) | `sealpost/` | Electron 44 (macOS 12 build: Electron 43), Node, OpenPGP.js 6, ImapFlow, Nodemailer, mailparser | `sealpost/package.json` → `version` (1.12.0) |
| **Sealpost Server** — sync server + **Sealpost Web** (webmail, also an iPhone home-screen app) | `sealpost-web/server/` | Plain PHP 8 (no framework, no PHP imap extension), SQLite, vanilla JS + OpenPGP.js in the browser | `sealpost-web/server/lib.php` → `SEALPOST_SERVER_VERSION` (1.10.0) |

The two version numbers are independent. Features that need both say so
(e.g. "pinned folders sync with Windows 1.10.0 and later").

Originally written with Claude on the web (claude.ai). Its sandbox paths
(`/home/claude/...`) still appear in `sealpost-web/devtest/`.

Don't put the maintainer's personal website, live install address or
server paths in the repo (code, examples, READMEs, tests) — it's public. Use
`example.com` in examples; links for downloads/updates go to GitHub
(`github.com/jeffbristow/sealpost/releases`). The live server files are **not**
mirrored in `C:\claude\Server_Copy`; this repo is the source of truth.

## Repository layout

```
sealpost/                  desktop app
  src/main/                Electron main process (all logic, Node access)
    bootstrap.js           entry point: loads newest .sealpost update file or the installed copy
    main.js                window, security hardening, ALL IPC handlers (sections 1–8)
    preload.js             the only UI↔main bridge: window.api.<name>() → {ok,data}|{ok:false,error}
    mail.js                IMAP (ImapFlow; one connection + IDLE push per account) and SMTP
    reader.js              opens incoming mail: PGP/MIME, inline PGP, Autocrypt, attachments
    compose.js + mime.js   builds outgoing mail byte-exact (RFC 3156 PGP/MIME)
    pgp.js                 keyring (<userData>/keyring) + OpenPGP ops + WKD / keys.openpgp.org lookup
    store.js               sealpost.json: accounts + settings (passwords via safeStorage/DPAPI)
    contacts.js            contacts.json: contacts, pinned keys, encrypt/sign rules
    sync.js                "Sync with my web server": zero-knowledge vault client
    cache.js               offline mail: encrypted local copy + outbox/pending/draft queues
    backup.js              .sealbackup (an OpenPGP symmetric message containing JSON)
    applock.js             PIN (scrypt) + Windows Hello via PowerShell
    asarinfo.js            reads package.json from an update file without locking it (EBUSY fix)
    updatecheck.js         "Check for updates": newest desktop release on GitHub + download (1.12.0)
    presets.js             provider server presets
  src/renderer/            UI: index.html, styles.css, app.js (one large file, ~3200 lines)
  build/                   icons, afterPack.js (stamps icon/version into the .exe),
                           make-update.js, Install-Update.bat/.ps1 (for 1.0.0 installs)
  test/                    pgp-test.js + one file per feature release (v110 … v191)
sealpost-web/
  server/                  everything uploaded to the website folder
    index.php              Sealpost Web page shell + strict CSP (no inline scripts, no CDNs)
    api.php                sync + sign-in API (ping, prelogin, setup, login, pull, push,
                           devices, revoke, changeAuth, destroy, pinSetup/pinUnlock/…)
    mail.php               browser → IMAP/SMTP bridge; credentials come with each request
    imap.php / smtp.php    self-contained IMAP and SMTP clients (raw sockets)
    keys.php               WKD + keys.openpgp.org lookup/publish for the browser (public keys only)
    update.php             one-click server updates: status / check / install / undo (1.10.0)
    lib.php                config, SQLite vault, validation, rate limits, device tokens,
                           section 8 = the updater (signed packages from GitHub)
    status.php             server status page
    config.example.php     template — copy to config.php (the real one is git-ignored)
    sw.js, manifest.webmanifest   iPhone home-screen app shell
    web/                   browser app: app.js (main screen), vault.js (sync crypto),
                           pgp.js, reader.js, compose.js, composer.js, people.js,
                           settings.js, tools.js, ui.js, faceid.js, update.js (1.10.0),
                           vendor/ (openpgp, postal-mime)
    README.txt             user-facing server README + full server changelog
  sealpost-check.php       standalone "can my host run this?" checker (upload alone)
  tools/release-server.js  packages + signs a server release, writes server-update.json
  devtest/                 stamp.sh (works on Windows since 1.10.0) + dev scripts from the
                           claude.ai sandbox (hard-coded /home/claude paths; not runnable as-is)
server-update.json         what installed servers read to find the newest server version
```

## How it works

### Desktop
- Renderer has no Node access. Every action is an IPC handler in `main.js`
  exposed through `preload.js`. While the app lock is engaged, main refuses
  every request except unlock.
- PGP/MIME needs byte-exact bodies, so `mime.js` builds the raw message and
  Nodemailer only transports it. Sent copies are encrypted to your own key.
- Incoming HTML renders in a sandboxed frame with no scripts; remote images
  are blocked until "Load images".
- Data: `%APPDATA%\Sealpost\` → `sealpost.json`, `contacts.json`,
  `keyring\public|private\`, `cache\` (offline), `updates\`, `sync.json`.

### Sync / vault (zero-knowledge) — `sync.js` ⇄ `web/vault.js` ⇄ `api.php`
- `master = PBKDF2-SHA256(passphrase, "sealpost:"+username, 600000)`;
  `loginKey = HKDF(master,"sealpost-auth")` (server stores an Argon2id hash);
  `wrapKey = HKDF(master,"sealpost-wrap")` (never leaves the device).
- A random vault key encrypts every item with AES-256-GCM, item id as AAD.
  The server only has the wrapped vault key and ciphertext.
- Items: `settings:main`, `account:<id>` (with passwords), `contact:<id>`,
  `key:<FP>`, `passphrase:<FP>`. Change detection: server sequence numbers +
  a local SHA-256 per item. Per-PC settings are excluded (`LOCAL_SETTINGS`).
- Only PBKDF2/HKDF/AES-GCM are used so the browser (Web Crypto) matches the
  desktop exactly.

### Sealpost Web
- The server never sees the vault passphrase, unlocked keys or decrypted mail.
  The browser decrypts the vault, then sends account credentials with each
  `mail.php` request (used for that one connection, never stored).
- Messages are built and signed/encrypted in the browser (`web/compose.js`,
  mirroring desktop `compose.js` + `mime.js`); `mail.php?send` only hands the
  finished bytes to SMTP and files the Sent copy.
- iPhone: home-screen PWA. PIN unlock = vault key encrypted with a key from
  PIN + a server-held secret released only for the right PIN (5 tries).
  Face ID (1.6.0) = passkey PRF encrypting the PIN. No push notifications
  by design (would need the mail password readable on the server).

## Rules that are easy to break

1. **Desktop and web implement the same formats twice.** Changes to
   compose/reader/MIME, draft format, vault crypto or sync item shapes must be
   made in both `sealpost/src/main/*.js` and `sealpost-web/server/web/*.js`,
   or mail/drafts/vaults stop being readable across them.
2. **Server version bump:** change `SEALPOST_SERVER_VERSION` in `lib.php`, then
   run `sealpost-web/devtest/stamp.sh` to add `?v=<version>` to every module
   import and rename the `sw.js` cache. Otherwise iPhones mix old and new
   cached scripts (the 1.6.1 bug). Add a "New in x.y.z" section to
   `server/README.txt`.
3. **Desktop version bump:** `sealpost/package.json` `version`. Mark new code
   with `// x.y.z:` comments (the codebase's convention), add a test file
   `test/vXYZ-test.js` and append it to the `test` script, and add an entry
   to "Version history" in `sealpost/README.md`.
4. **Never commit `sealpost-web/server/config.php`** (contains the setup code).
   Edit `config.example.php` for template changes. When deploying an update,
   upload everything except `config.php`, always the whole `web/` folder.
5. `index.php` CSP: no inline scripts/styles and no CDNs — new scripts go in `web/`.
6. Code style: plain JS (no TypeScript, no bundler), big section-header
   comments at the top of each file ("Sections: 1. … 2. …"), short `// x.y.z:`
   notes on changes. Match it.

## Commands

```bash
cd sealpost
npm install
npm test               # all suites; v140/v150 start `php -S` with the server files
npm start              # run the desktop app
npm run dist           # Windows installer → dist/
npm run dist:linux     # AppImage + .deb
npm run update-file    # dist/update/Sealpost-<ver>.sealpost (+ zip with Install-Update.bat)
```

PHP on this PC: `C:\Users\jeffb\tools\php-8.4\php.exe` (not on PATH by
default). Its `php.ini` doesn't load SQLite, which v140/v150 need. Enable it for
one run without touching the global ini:

```bash
export PATH="/c/Users/jeffb/tools/php-8.4:$PATH"
export PHP_INI_SCAN_DIR=<dir containing an ini with: extension=pdo_sqlite / extension=sqlite3>
```

v140/v150 are skipped (not failed) when `php` isn't found, so check that their
pass counts show up.

## Releases

- **Desktop updates are unsigned and come from GitHub releases** (1.12.0+):
  Settings → About & updates → Check for updates (`updatecheck.js`) reads
  `api.github.com/repos/jeffbristow/sealpost/releases`, takes the newest
  non-draft, non-prerelease `v<x.y.z>` tag (`server-v…` tags are ignored),
  and downloads its `Sealpost-<x.y.z>.sealpost` asset — so every desktop
  release MUST attach that file under exactly that name. Only on click; no
  background checks. Install update file… still takes a file picked by hand
  (`bootstrap.js` runs the newest valid one; a broken update is marked bad
  and skipped).
- **Mac installers** (1.11.0+): `.github/workflows/mac.yml`, run by hand
  (`gh workflow run mac.yml -f release_tag=<tag>`) on a GitHub Mac. Two
  builds × arm64/x64: regular (Electron from package.json, macOS 13+) and
  `macOS12` (Electron 43.x installed `--no-save`, `LSMinimumSystemVersion 12.0`).
  Ad-hoc signed (`mac.identity "-"`, no Apple account); the workflow checks
  `codesign --verify`, the minimum macOS and the bundled Electron version.
  Mac-specific code: `macMenu()` in main.js (menu bar; Select All asks the
  window), `MOD(e)` in renderer app.js (⌘ = Ctrl; not for Q). Nobody here can
  run the Mac app — Jeff tests it on his Mac. When Electron 43 stops getting
  security fixes, decide whether to keep supporting macOS 12.
- **Linux installers** can't be built on this Windows PC (no WSL/Docker).
  GitHub Actions does it: `.github/workflows/linux.yml`, run by hand
  (`gh workflow run linux.yml -f release_tag=<tag>`). It runs the tests, builds
  the `.deb` + AppImage on Ubuntu 22.04 and attaches them to that release.
- Releases: one per desktop version, tag `v<desktop version>` (e.g. `v1.10.0`),
  holding the Windows installer, the `.sealpost` update file, the Linux
  `.deb` + AppImage, and `Sealpost-Web-Server-<server version>.zip` (built with
  `git archive` from `sealpost-web/server`, so it never contains `config.php`).
- **Server/web — one-click updates (1.10.0+):** installed servers read
  `server-update.json` (raw.githubusercontent.com, `main`) and install only zips
  signed with the Sealpost update key (Ed25519; public half = `UPDATE_PUBKEY` in
  `lib.php`; private half = `~/.sealpost/update-signing-key.pem` on Jeff's PC,
  never in the repo — losing it means servers can't take updates until the new
  public key is uploaded by hand). To release server version X:
  1. bump `SEALPOST_SERVER_VERSION`, run `devtest/stamp.sh`, add "New in X" to
     `server/README.txt`, commit;
  2. `node sealpost-web/tools/release-server.js --note "…"` (refuses uncommitted
     server changes, an unstamped `sw.js`, or a key that doesn't match);
  3. `gh release create server-vX --latest=false …zip …zip.sig` FIRST,
  4. then commit + push `server-update.json` (servers must never be pointed at
     a file that isn't downloadable yet).
  Servers older than 1.10.0 have no updater: upload 1.10.0 by hand once.
  `status.php` should show all green and the new server version.
- Tests for the updater: `sealpost/test/server-update-test.js` (needs php with
  pdo_sqlite, zip, curl, sodium — the local ini needs `extension=zip` too).
- Changelogs: desktop → "Version history" in `sealpost/README.md`;
  server/web → "New in x.y.z" in `sealpost-web/server/README.txt`. Update
  the right one with every release.

## Known gaps

- License is GPL-3.0 (`LICENSE`, `package.json` `"GPL-3.0-only"`).
- No OAuth2 (Gmail/Microsoft need app passwords); no S/MIME; installer is not code-signed.
