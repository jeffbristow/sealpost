# Sealpost — PGP Email Client

Sealpost is a desktop email client with OpenPGP built in: key generation and
management, signing, encrypting, decrypting and verifying — alongside normal
IMAP/SMTP email. It runs on Windows 11, macOS 12+ and Linux, and can sync with your own
**Sealpost Server**, which also gives you **Sealpost Web** (webmail with the
same PGP features, installable on an iPhone home screen). See
[`../sealpost-web/server/README.txt`](../sealpost-web/server/README.txt).

## Install (ready-made installer)

Download the installer for your system from the
[GitHub releases page](https://github.com/jeffbristow/sealpost/releases).

**Windows**
1. Run `Sealpost Setup <version>.exe`.
2. Windows SmartScreen will say "Windows protected your PC" because the
   installer is not code-signed. Click **More info → Run anyway**.
3. Choose the install folder, finish, and launch Sealpost from the Start menu
   or desktop shortcut.

**Linux**
- `.deb` (Ubuntu, Debian, Mint): `sudo apt install ./Sealpost-<version>-amd64.deb`
- AppImage (any distribution): make `Sealpost-<version>-x86_64.AppImage`
  executable and run it.

**Mac**
| Your Mac | File |
|----------|------|
| macOS 13 Ventura or newer, Apple Silicon (M1/M2/M3/M4…) | `Sealpost-<version>-arm64.dmg` |
| macOS 13 Ventura or newer, Intel | `Sealpost-<version>-x64.dmg` |
| macOS 12 Monterey, Apple Silicon | `Sealpost-<version>-macOS12-arm64.dmg` |
| macOS 12 Monterey, Intel | `Sealpost-<version>-macOS12-x64.dmg` |

(Apple menu → About This Mac shows your macOS version and chip.)
1. Open the .dmg and drag **Sealpost** onto **Applications**.
2. Open Sealpost from Applications. The app isn't signed with an Apple
   Developer certificate, so macOS says it can't check it — click **Done** / **OK**.
3. **System Settings → Privacy & Security**, scroll down to "Sealpost was
   blocked…" and click **Open Anyway** (on macOS 12: right-click Sealpost in
   Applications → **Open** → **Open**). Only needed the first time.

The macOS 12 build uses an older Electron (43), because Electron 44 needs
macOS 13. Both builds take the same `.sealpost` update files.

## Updating (no reinstall)

- **Settings → About & updates → Check for updates** asks GitHub
  ([github.com/jeffbristow/sealpost/releases](https://github.com/jeffbristow/sealpost/releases))
  for a newer version and offers to download and install it. Sealpost
  restarts into the new version.
- Or download the `.sealpost` file from the
  [releases page](https://github.com/jeffbristow/sealpost/releases) yourself:
  **Settings → About & updates → Install update file…** and pick it.
- **Still on 1.0.0?** Unzip `Sealpost-Update-x.y.z.zip` into a folder and
  double-click `Install-Update.bat`. It finds your install, closes Sealpost,
  backs up the old code (`resources\app.asar.backup`), applies the update,
  and restarts Sealpost.
- Accounts, settings and PGP keys are never touched by an update.
- A newer full installer always wins over an older update file. If an update
  file fails to start, it is marked bad and the installed version runs instead.

## First run

1. **Add your account** (opens automatically). Pick a provider preset
   (Gmail, Outlook, Yahoo, iCloud, Fastmail, Proton Bridge, Zoho, Zoho paid
   plans, cPanel) or enter servers manually. Click **Test connection**, then
   **Save**.
   - Gmail / Yahoo / iCloud / Fastmail need an *app password*, not your normal password.
   - Already use Sealpost elsewhere? Choose **Restore from a backup**, or set up
     **Sync with my web server** to bring in your accounts, contacts and keys.
2. Sealpost offers to **create a PGP key** for that address. Choose a strong
   passphrase — it cannot be recovered.
3. In **Keys**, select your key and click **Backup secret key…** and
   **Export revocation certificate…**. Store both offline.

## Features

| Area | What it does |
|------|--------------|
| Mail | Multiple IMAP accounts, folders in their real hierarchy with unread counts, search, paging, flag, read/unread, move (or drag onto a folder), delete (to Trash), reply / reply-all / forward, attachments, notifications |
| Folders | New, rename, move and delete folders; pin folders to **Favorites**; **All Inboxes** when you have 2+ accounts; optional **conversation view** per account |
| Selecting | Tick boxes, Ctrl-click / Shift-click, Ctrl+A — then mark read/unread, flag, move or delete together |
| Send as | Extra "Send as" addresses per account (e.g. Zoho "Send mail as"); replies use the address the message was sent to |
| Reading safety | HTML mail rendered in a sandboxed frame with no scripts; remote images (tracking pixels) blocked until you click *Load images*; links open in your browser |
| Encrypt | PGP/MIME (RFC 3156). Optional **Hide subject** (protected headers). Copy encrypted to yourself so Sent mail stays readable |
| Sign | PGP/MIME detached signatures; inline signed blocks verified too |
| Decrypt / verify | PGP/MIME, inline PGP, sign+encrypt combos, encrypted `.pgp/.gpg` attachments, signer vs. From-address check, BAD-signature warnings |
| Keys | Generate (Curve25519 or RSA-4096, with expiry), import from file / paste / attachments / Autocrypt headers, look up online (WKD + keys.openpgp.org), publish to keys.openpgp.org, trust levels, extend expiry, change passphrase, export public / secret / revocation cert, revoke, delete. Expiry warnings 30 days ahead |
| Passphrases | "Remember on this computer" (locked to your login), or "Remember on all my devices" (kept in your encrypted sync vault) |
| Contacts | Name, addresses, assigned PGP key, Always-encrypt / signing rules, notes. Autocomplete in To/Cc/Bcc. Keys arriving in mail can be added in one click. Warns when a contact signs with or sends a different key |
| Drafts | Autosaved, encrypted to your own key, stored in the server's Drafts folder; open in Sealpost or Sealpost Web |
| Instant mail | One push (IMAP IDLE) connection per account; Live / Offline indicator; reconnects automatically; slow safety check every 10 min |
| Sync | **Sync with my web server**: accounts (with passwords), contacts, keys and settings stay the same on every PC and in Sealpost Web. End-to-end encrypted; your server can't read any of it |
| Backup | One `.sealbackup` file (OpenPGP, AES-256) with accounts, passwords, settings, contacts, keys; restore on a new PC in a few clicks. `gpg --decrypt` can open it in an emergency |
| Offline mail | Encrypted (to your PIN) copy of recent mail; works with no connection; saved folders show instantly; Outbox sends automatically on reconnect |
| App lock | PIN / Windows Hello on start, after inactivity, on Windows lock or sleep. While locked Sealpost refuses every request except unlocking |
| Composer | Rich or plain text. Live per-recipient key status (green = key found, amber = missing → click to search online). Replies to encrypted mail default to encrypted |
| PGP Tools | Encrypt / sign / decrypt / verify / import any pasted text — use with webmail, chat, forms |

Keyboard: `Ctrl+N` new message · `Ctrl+R` reply · `Ctrl+Enter` send ·
`Del` delete · `Ctrl+Q` / `Ctrl+U` mark read / unread · `Ctrl+A` select all ·
`Esc` clear selection · `↑/↓` or `j/k` next/previous · `F5` refresh.
On a Mac, `⌘` works in place of `Ctrl` (except `⌘Q`, which quits — use `Ctrl+Q`
to mark read), and `⌘,` opens Settings.

## Where your data lives

Windows: `%APPDATA%\Sealpost\` · Mac: `~/Library/Application Support/Sealpost/` · Linux: `~/.config/Sealpost/`
- `sealpost.json` — accounts and settings. Passwords are encrypted with
  Windows DPAPI (your Windows login), the Mac Keychain, or on Linux your
  login keyring (GNOME Keyring / KDE Wallet).
- `contacts.json` — contacts
- `keyring\public\` — public keys
- `keyring\private\` — your secret keys, always passphrase-encrypted, plus revocation certificates
- `cache\` — offline mail, encrypted (only with Offline mail turned on)
- `sync.json` — sync state (only with Sync turned on)
- `updates\` — installed update files

Back up with **Settings → Backup**, or at least keep the `keyring` folder safe.
Losing your secret key means losing access to mail encrypted to it.

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
npm test               # self-tests; the sync tests also need php (with pdo_sqlite) on PATH
npm start              # run without installing
npm run dist           # Windows installer -> dist\Sealpost Setup <version>.exe
npm run dist:portable  # single portable .exe, no install
npm run dist:linux     # AppImage + .deb
npm run dist:mac       # .dmg for Apple Silicon + Intel (on a Mac; releases use .github/workflows/mac.yml)
npm run update-file    # dist\update\Sealpost-<version>.sealpost (+ the 1.0.0 update zip)
```

## Project layout

```
src/main/bootstrap.js  Entry point: runs the newest installed update file, or the installed copy
src/main/main.js       Electron main process: window, security, IPC handlers
src/main/preload.js    Bridge exposing a fixed API to the UI
src/main/store.js      Accounts + settings (protected passwords)
src/main/contacts.js   Contacts
src/main/pgp.js        OpenPGP engine + keyring + online key lookup
src/main/mime.js       Raw MIME builder/parser (byte-exact for PGP/MIME)
src/main/compose.js    Builds outgoing mail with sign/encrypt
src/main/reader.js     Opens incoming mail, decrypts/verifies, attachments
src/main/mail.js       IMAP (ImapFlow) + SMTP (Nodemailer), folders, IDLE push
src/main/sync.js       Sync with my web server (end-to-end encrypted vault)
src/main/cache.js      Offline mail (encrypted local copy + outbox)
src/main/backup.js     .sealbackup create / restore
src/main/applock.js    PIN + Windows Hello
src/main/asarinfo.js   Reads update files without locking them
src/main/updatecheck.js  Check for updates on GitHub releases (1.12.0)
src/main/presets.js    Provider server settings
src/renderer/          UI: index.html, styles.css, app.js
build/                 Icons, afterPack hook (stamps icon into the .exe), update builder
test/                  Self-tests (pgp-test.js + one per feature release)
```

## Version history

- **1.13.0** — New: **addy.io aliases** (Settings → addy.io aliases → "I use addy.io"). Writing through an addy.io alias puts the real recipient inside the To address (`shop+sam=example.org@example.com` goes to `sam@example.org`); with the setting on, Sealpost encrypts to, looks up online and assigns the key of that real address, while the To address stays as it is. addy.io's own domains and your "Send as" domains are recognised automatically; list other custom domains in the same place. The composer's key chips show the real recipient ("via addy.io"), and warn that a signature or attached key shows the addresses on your key. "Find key online" also assigns an imported key to the contact for that address if it had none (as Sealpost Web does). The setting syncs with Sealpost Web (server 1.11.0+).
- **1.12.0** — New: **Check for updates** (Settings → About & updates) looks for a newer release on GitHub and downloads and installs its update file; **Releases on GitHub** opens the releases page. Example addresses in Settings now use example.com.
- **1.11.0** — **Mac**: Sealpost for macOS 13+ and, as a separate build, macOS 12 (Apple Silicon and Intel). The standard Mac menu bar (⌘C / ⌘V / ⌘Z / ⌘Q, ⌘, for Settings); ⌘ works in place of Ctrl in Sealpost's shortcuts, and ⌘-click selects messages. Passwords are kept with the Mac Keychain. Windows and Linux: no changes besides the version number.
- **1.10.0** — New: **folder management** (new folder / subfolder, rename, move, delete; Inbox, Sent, Drafts, Trash etc. are protected), **pinned folders** under Favorites, drag messages onto a folder to move them. **All Inboxes** (2+ accounts): every Inbox in one list; replies go out from the right account. **Conversation view**, per account and off unless turned on: replies are grouped under one line. Pins and the conversation switch sync with Sealpost Web (server 1.8.0+).
- **1.9.2** — Folders and the first page of messages saved for Offline mail show instantly; the server's up-to-date list replaces them a moment later.
- **1.9.1** — Fix: folders are shown in their real hierarchy (subfolders under their parent; container folders that hold only other folders can't be opened). The Move list is indented the same way.
- **1.9.0** — New: **"Send as" addresses** per account (Settings → Mail accounts → Edit). The composer's From list offers each one; replies use the address the message was sent to; drafts keep their address. Signs with a key for that address if you have one. Syncs with Sealpost Web.
- **1.8.0** — **Linux** builds (AppImage and .deb). Passwords use the login keyring (GNOME Keyring / KDE Wallet); without one, Settings says so and "Remember passphrase" is unavailable. The AppImage runs where the Chromium sandbox is blocked (Ubuntu 23.10+). The data folder is private to your user.
- **1.7.0** — New: **select several messages** (tick boxes, Ctrl-click, Shift-click, Ctrl+A, Esc to clear) to mark read / unread, flag, move or delete together. Zoho paid plans / Zoho Workplace preset (the "pro" servers).
- **1.6.0** — New: **read / unread** controls: click the dot beside a message (a whole conversation at once), Ctrl+Q / Ctrl+U, mark a whole folder as read (works offline too). **Right-click menus** for messages and folders.
- **1.5.0** — New: **"Remember passphrase on all my devices"** — the key's passphrase travels in your encrypted sync vault, so every PC and Sealpost Web unlock it. Changing the passphrase updates it everywhere.
- **1.4.0** — New: **Sync with my web server**. Accounts (with passwords), contacts, keys and settings stay the same on every PC and in **Sealpost Web**, through the Sealpost Server on your own website. Zero-knowledge: everything is encrypted on your PC with a vault passphrase that never leaves it. Syncs shortly after start, then every 5 minutes, and after unlocking.
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

## Known limits

- OAuth2 sign-in (Microsoft/Google "Sign in with…") is not implemented; use app passwords. Some Microsoft 365 tenants disable password IMAP entirely.
- No S/MIME.
- Installer is unsigned (SmartScreen prompt). A code-signing certificate can be added via electron-builder's `win.certificateFile` setting.
- Sealpost only checks for updates when you click **Check for updates**; it never checks on its own. Update files are not signed (they come over HTTPS from GitHub).

## License

GPL-3.0 — see [LICENSE](../LICENSE).
