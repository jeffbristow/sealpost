# Sealpost — PGP Email Client for Windows 11

Sealpost is a desktop email client with OpenPGP built in: key generation and
management, signing, encrypting, decrypting and verifying — alongside normal
IMAP/SMTP email.

## Install (ready-made installer)

1. Run `Sealpost Setup 1.0.0.exe`.
2. Windows SmartScreen will say "Windows protected your PC" because the
   installer is not code-signed. Click **More info → Run anyway**.
3. Choose the install folder, finish, and launch Sealpost from the Start menu
   or desktop shortcut.

## Updating (no reinstall)

- **From 1.0.0:** unzip `Sealpost-Update-x.y.z.zip` into a folder and double-click
  `Install-Update.bat`. It finds your install, closes Sealpost, backs up the old
  code (`resources\app.asar.backup`), applies the update, and restarts Sealpost.
- **From 1.0.1 on:** Settings → **About & updates** → **Install update file…** and
  pick the `.sealpost` file. Sealpost restarts into the new version.
- Accounts, settings and PGP keys (in `%APPDATA%\Sealpost`) are never touched.
- Developers: `npm run update-file` builds both files into `dist\update\`.

### Version history
- **1.3.1** — New app icon: a harbor seal holding a sealed envelope (the green padlock "wax seal"). Existing desktop / Start menu / pinned-taskbar shortcuts are switched to the new icon automatically; the icon inside Sealpost.exe changes with the next full install. Icon source: `build/icon-src/sealpost-icon.svg`.
- **1.3.0** — New: **Offline mail**. An encrypted copy of recent mail (default: last 30 days, messages up to 10 MB, 500 MB cap) is kept on this PC so you can read, search and write without a connection. The copy is encrypted (AES-256-GCM) with a random key that is locked to your **app-lock PIN** (scrypt, ~1 s per guess) and to your own PGP key ("Forgot PIN"); PGP mail stays PGP-encrypted inside it. **Outbox**: messages written offline are encrypted/signed immediately and sent automatically when the connection returns; read/flag changes and drafts are queued too. Requires App lock with a PIN of 6+ digits (8+ recommended); Windows Hello unlock is off while Offline mail is on.
- **1.2.0** — New: **Instant new mail** (IMAP IDLE push: new mail, and mail read/deleted elsewhere, shows up within a second; "● Live" indicator; auto-reconnect after network loss or sleep; clickable Windows notifications; taskbar flash). **Backup & restore** (Settings → one passphrase-protected `.sealbackup` file with accounts + passwords, settings, contacts and all keys; restore merges and never deletes; first-run screen offers "Restore from a backup"). The backup is a standard OpenPGP file, so `gpg --decrypt` can open it in an emergency.
- **1.1.0** — New: **Contacts** (assigned keys always used, per-contact Always-encrypt / signing rules, address autocomplete, one-click add from received mail, key-change warnings). **Encrypted drafts** (autosaved every few seconds to your server's Drafts folder, encrypted to your own key; reopen from Drafts). **Key expiry warnings** 30 days ahead + **Extend expiry** (same key and fingerprint). **App lock** (PIN, optional Windows Hello, locks on start / inactivity / Windows lock / sleep; forgot-PIN unlock with any key passphrase). **Rich text** composing (bold, italic, underline, lists, quotes, links, size, color) sent with a plain-text version.
- **1.0.3** — Fix: "EBUSY: resource busy or locked" when using Install update file… on Windows (the update file was left open while being checked). Leftover files from the failed attempt are cleaned up automatically. Includes everything from 1.0.2.
- **1.0.2** — New: *Remember passphrase*. Tick "Remember on this computer" when unlocking (or Keys → Remember passphrase…) and the key unlocks automatically, even after restarting. The passphrase is encrypted with Windows DPAPI (your Windows login) in `keyring\remembered.json`. Keys → Forget saved passphrase turns it off.
- **1.0.1** — Fix: decrypted HTML emails showed a blank white "Formatted" view when the
  key was unlocked after opening the message. Fix: HTML-only emails (e.g. Proton) now have
  a Plain text version, so replies quote the original. New: in-app updates.
- **1.0.0** — First release.

## First run

1. **Add your account** (opens automatically). Pick a provider preset
   (Gmail, Outlook, Yahoo, iCloud, Fastmail, Proton Bridge, Zoho, cPanel) or
   enter servers manually. Click **Test connection**, then **Save**.
   - Gmail / Yahoo / iCloud / Fastmail need an *app password*, not your normal password.
2. Sealpost offers to **create a PGP key** for that address. Choose a strong
   passphrase — it cannot be recovered.
3. In **Keys**, select your key and click **Backup secret key…** and
   **Export revocation certificate…**. Store both offline.

## Features

| Area | What it does |
|------|--------------|
| Mail | Multiple IMAP accounts, folders with unread counts, search, paging, flag, mark unread, move, delete (to Trash), reply / reply-all / forward, attachments, new-mail notifications, auto refresh every 2 min |
| Reading safety | HTML mail rendered in a sandboxed frame with no scripts; remote images (tracking pixels) blocked until you click *Load images*; links open in your browser |
| Encrypt | PGP/MIME (RFC 3156). Optional **Hide subject** (protected headers). Copy encrypted to yourself so Sent mail stays readable |
| Sign | PGP/MIME detached signatures; inline signed blocks verified too |
| Decrypt / verify | PGP/MIME, inline PGP, sign+encrypt combos, encrypted `.pgp/.gpg` attachments, signer vs. From-address check, BAD-signature warnings |
| Keys | Generate (Curve25519 or RSA-4096, with expiry), import from file / paste / attachments / Autocrypt headers, look up online (WKD + keys.openpgp.org), publish to keys.openpgp.org, trust levels, change passphrase, export public / secret / revocation cert, revoke, delete |
| Contacts | Name, addresses, assigned PGP key, Always-encrypt / signing rules, notes. Autocomplete in To/Cc/Bcc. Keys arriving in mail can be added in one click. Warns when a contact signs with or sends a different key |
| Drafts | Autosaved, encrypted to your own key, stored in the server's Drafts folder; click a draft to keep writing |
| Instant mail | One push (IMAP IDLE) connection per account; Live / Offline indicator; reconnects automatically; slow safety check every 10 min |
| Backup | One `.sealbackup` file (OpenPGP, AES-256) with accounts, passwords, settings, contacts, keys; restore on a new PC in a few clicks |
| Offline mail | Encrypted (to your PIN) copy of recent mail; works with no connection; Outbox sends automatically on reconnect; saved messages open instantly |
| App lock | PIN / Windows Hello on start, after inactivity, on Windows lock or sleep. While locked Sealpost refuses every request except unlocking |
| Composer | Live per-recipient key status (green = key found, amber = missing → click to search online). Replies to encrypted mail default to encrypted |
| PGP Tools | Encrypt / sign / decrypt / verify / import any pasted text — use with webmail, chat, forms |

Keyboard: `Ctrl+N` new message · `Ctrl+R` reply · `Ctrl+Enter` send · `Del` delete · `↑/↓` or `j/k` next/previous · `F5` refresh.

## Where your data lives

`%APPDATA%\Sealpost\`
- `sealpost.json` — accounts and settings. Passwords are encrypted with Windows DPAPI (tied to your Windows login).
- `keyring\public\` — public keys
- `keyring\private\` — your secret keys, always passphrase-encrypted, plus revocation certificates

Back up the `keyring` folder. Losing your secret key means losing access to mail encrypted to it.

## Compatibility

Tested two-way against GnuPG 2.4 (the engine behind Kleopatra/Gpg4win,
Thunderbird's external GPG mode, and Enigmail): Sealpost reads GnuPG PGP/MIME
encrypted+signed mail and verifies GnuPG signatures; GnuPG decrypts Sealpost
mail and reports "Good signature". Uses OpenPGP.js (the library inside Proton
Mail and Mailvelope).

## Building from source

Requires Node.js 20+ (https://nodejs.org).

```
cd sealpost
npm install
npm test            # PGP engine self-test
npm start           # run without installing
npm run dist        # builds dist\Sealpost Setup 1.0.0.exe
npm run dist:portable  # single portable .exe, no install
```

Or just double-click `build-windows.bat`.

## Project layout

```
src/main/main.js      Electron main process: window, security, IPC handlers
src/main/preload.js   Bridge exposing a fixed API to the UI
src/main/store.js     Accounts + settings (DPAPI-protected passwords)
src/main/pgp.js       OpenPGP engine + keyring + online key lookup
src/main/mime.js      Raw MIME builder/parser (byte-exact for PGP/MIME)
src/main/compose.js   Builds outgoing mail with sign/encrypt
src/main/reader.js    Opens incoming mail, decrypts/verifies, attachments
src/main/mail.js      IMAP (ImapFlow) + SMTP (Nodemailer)
src/main/presets.js   Provider server settings
src/renderer/         UI: index.html, styles.css, app.js
build/                Icon + afterPack hook (stamps icon into the .exe)
test/pgp-test.js      Self-test
```

## Known limits

- OAuth2 sign-in (Microsoft/Google "Sign in with…") is not implemented; use app passwords. Some Microsoft 365 tenants disable password IMAP entirely.
- No drafts folder sync, no S/MIME.
- Installer is unsigned (SmartScreen prompt). A code-signing certificate can be added via electron-builder's `win.certificateFile` setting.
