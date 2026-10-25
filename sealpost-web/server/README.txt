SEALPOST SERVER 1.10.0  —  Sync + Sealpost Web + iPhone app
======================================================================

What's in it
  Sync server (1.0.0)  keeps Sealpost's accounts, contacts, keys and
                       settings the same on every PC (end-to-end encrypted).
  Sealpost Web         read AND write mail from any browser, PGP included:
                       compose / reply / forward, sign, encrypt, hide
                       subject, attachments, encrypted drafts (they open
                       in Sealpost on your PC too), contacts, keys.
                       Sign in with your VAULT username + passphrase.
                       Decryption and signature checks happen in your
                       browser; the server never sees your passphrase,
                       your keys unlocked, or decrypted mail.
  iPhone app (1.5.0)   the same Sealpost Web, installed on the home
                       screen from Safari — no App Store needed —
                       opened with Face ID or a PIN.

Files
  index.php    Sealpost Web (the page you open)
  status.php   server status page (was index.php in 1.0.0)
  api.php      sync + sign-in
  mail.php     connects to your mail server for the web page
  imap.php     the mail-server (IMAP) connection code
  smtp.php     sends finished messages through your SMTP server (1.2.0)
  keys.php     finds people's public keys online / publishes yours (1.4.0)
  update.php   one-click server updates (1.10.0)
  manifest.webmanifest  name + icons for the home-screen app (1.5.0)
  web/faceid.js  Face ID unlock (1.6.0)
  sw.js        lets the home-screen app start quickly; keeps only the
               app's own files, never mail or vault data (1.5.0)
  lib.php      shared code (database, checks, rate limiting)
  config.example.php  template for config.php — your settings, including
               the one-time SETUP CODE (config.php itself is not in the
               download, so an update can never overwrite yours)
  web/        the web app (scripts, styles, icons, OpenPGP.js)
  .htaccess    blocks config/lib/imap/smtp.php, forces HTTPS, script types
               (some FTP programs hide files starting with a dot —
                make sure it is uploaded)

Updating from an earlier version
  Upload everything into the same folder, replacing the old files.
  Keep the config.php already on your server (the download has none).
  Include the whole web/ folder. Your vault is untouched.

New install
  1. Upload all files into one folder, e.g. public_html/mysite/SealPost/
  2. Copy config.example.php to config.php and change 'setup_code' to a
     code only you know (any letters/numbers). Without config.php, vault
     creation stays switched off.
  3. Open https://<your-site>/<folder>/status.php — all lines green.
  4. In Sealpost on your PC: Settings -> Sync with my web server ->
     Set up sync (address, username, vault passphrase, setup code).
  5. Open https://<your-site>/<folder>/ and sign in.

Good to know
  - Closing the browser tab signs you out; 30 minutes without activity
    also signs you out. A web sign-in unused for 12 hours expires.
  - Each browser sign-in appears under Devices in Sealpost on your PC,
    where you can sign it out.
  - Messages are built — and signed/encrypted — in your browser; the
    server only passes the finished, already-encrypted message to your
    SMTP server and saves a copy in Sent.
  - Contacts and keys you change on the web sync to your PCs.
  - "Remember passphrase on all my devices" (Keys) keeps that key's
    passphrase in your encrypted vault so every device unlocks it.
  - Read / unread: click the dot beside a message, use the button in
    the message, press U, or right-click a message. The ✓ button above
    the list (or right-click a folder) marks a whole folder as read. (1.3.0)
  - Messages over 40 MB: open them in Sealpost on your PC.

New in 1.4.0
  - Settings page: sign / encrypt defaults, text format, images, how
    long keys stay unlocked, messages per page.
  - Mail accounts: add, edit (incl. signatures), test, delete — with
    provider presets (incl. Zoho paid plans: imappro / smtppro).
  - Import a Sealpost backup (.sealbackup) — opened in your browser,
    added to your vault, synced to your PCs.
  - Keys: Find online (Web Key Directory + keys.openpgp.org), extend
    expiry, change passphrase, revoke, publish. The "no key" chips in
    the composer open the online search too.
  - PGP Tools: encrypt / sign / decrypt / verify / import pasted text.
  - Select several messages (☐ button, Ctrl-click, Shift-click,
    Ctrl+A) to mark read / unread, flag, move or delete together.

New in 1.5.0 — Sealpost on your iPhone
  Install:
    1. On the iPhone, open Safari (it must be Safari) and go to
       your Sealpost address, e.g. https://example.com/sealpost/
    2. Tap the Share button (square with an arrow) -> Add to Home Screen
       -> Add. A Sealpost icon appears on the home screen.
    3. Open Sealpost FROM THAT ICON and sign in with your vault username
       and passphrase. (The installed app keeps its own sign-in,
       separate from Safari — signing in inside Safari doesn't carry over.)
    4. It offers "Unlock with a PIN": choose 6–12 digits. From then on
       you open Sealpost with the PIN.
  How the PIN stays safe:
    - The phone keeps your vault key encrypted with a key made from your
      PIN plus a random secret that only your server holds. The server
      only hands out that secret for the right PIN.
    - 5 wrong PINs: PIN unlock is wiped and the phone must sign in with
      the vault passphrase again.
    - Sealpost locks itself after 30 minutes without use (or when you tap
      Lock in the menu). A phone not used for 30 days must sign in with
      the passphrase again.
    - "Sign out" in the menu removes the phone completely (PIN included).
      You can also sign it out from Sealpost on your PC under Devices.
  Also: unread count on the app icon (iOS 16.4 or newer), screen edges /
  notch handled, larger touch targets. Settings -> This device turns the
  PIN on/off or changes it.
  Not possible as a home-screen app (Apple limits / zero-knowledge):
    - New-mail push notifications. They would need your mail password
      stored readable on the server, which Sealpost deliberately never
      does. New mail shows when you open the app.

New in 1.6.0 — Face ID
  - Needs iOS 18 or newer. After you choose a PIN, Sealpost offers
    "Unlock with Face ID?" -> Use Face ID. iOS asks to save a passkey
    for Sealpost in your iCloud Keychain: allow it.
  - Opening the app then asks for Face ID right away; the PIN stays as
    the backup (and "Unlock with Face ID" is on the PIN screen).
  - Already using a PIN? Settings -> This device -> Turn on Face ID…
    (asks for your PIN once).
  - How it stays safe: your PIN is kept on the phone encrypted with a
    key that the passkey only releases after a successful Face ID scan.
    Face ID then unlocks exactly like typing the PIN, so the server's
    checks (5 wrong tries, 30 days unused) still apply.
  - Changing the PIN turns Face ID off; Sealpost offers to set it up
    again straight away. Turning Face ID off leaves the passkey in the
    iPhone's Passwords app, where you can delete it ("Sealpost").
  - Nothing new to configure on the server; only files changed.
  1.6.1: fixes "vault.setDeviceFace is not a function" — the phone could
  keep an old copy of a script next to new ones. Every script is now
  loaded with the version number, so an update always arrives complete.
  ALWAYS upload the whole web/ folder when updating.

New in 1.7.0 — "Send as" addresses
  - Settings -> Mail accounts -> Edit -> "Send as" addresses: one per
    line, e.g.   Your Name <you@example.com>
    (Set the address up in your mail provider first — Zoho Mail ->
    Settings -> Mail Accounts -> "Send mail as".)
  - The From list in the composer then offers each address. Replies use
    the address the message was sent to; drafts keep their address.
  - Sent through the account's own SMTP server, saved in its Sent folder.
  - PGP: signs with a key for that address if you have one, otherwise
    with the account's key (the composer says which).
  - The list syncs with Sealpost on your PCs (Windows 1.9.0 and later).

New in 1.8.0 — folders, All Inboxes, conversations
  - Folder management: right-click a folder (or tap its ⋯ on a phone):
    Pin to top, New subfolder, Rename, Move folder to…, Delete folder.
    ＋ next to an account name makes a new top-level folder. Inbox, Sent,
    Drafts, Trash etc. can't be renamed or deleted. Drag messages onto a
    folder to move them (computer browsers).
  - Pinned folders appear under Favorites at the top of the folder list
    and sync with Sealpost on your PCs (Windows 1.10.0 and later).
  - All Inboxes (Favorites, when you have 2+ accounts): every Inbox in
    one list. Replies go out from the right account automatically.
  - Conversation view, per account, OFF unless turned on: the 💬 button
    above the list, ⋯ next to the account name, or Settings -> Mail
    accounts -> Edit. Replies are grouped under one line; click it to
    see the whole conversation.

New in 1.9.0 — iPhone layout reworked (Apple's guidelines)
  - Every button and row is at least 44 points (Apple's minimum);
    text is ~17 pt and follows the iPhone's Text Size setting
    (Settings -> Display & Brightness -> Text Size).
  - Reading a message: ‹ Back and ⋯ at the top; a toolbar at the
    bottom: Delete · Move · Flag · Reply (Reply offers Reply all and
    Forward). ⋯ has Mark unread, Add contact, View source.
  - ✎ New message button bottom-right of the list. The list's ⋯ menu
    holds Select, Mark all read, Conversation view, Refresh.
  - Press and hold a message for its menu. Swipe left = delete, swipe
    right = read / unread. Pull the list down to refresh.
  - Writing: Send is top-right, ✕ top-left.
  - Menus open as a sheet at the bottom of the screen.
  - Computers: unchanged.
  1.9.1: less empty space under the message list ("Load older messages"
  sits beside the ✎ button); bigger ☰ button and folder name.
  1.9.2: fixes the empty strip at the bottom on iOS 26 (status bar style
  "black"). iPhone: remove the Sealpost icon and add it to the Home Screen
  again once, then sign in and set up PIN / Face ID again.

New in 1.10.0 — one-click updates
  - When a newer Sealpost Server is out, Sealpost Web says so after you
    sign in (a card at the top of the menu). Click Update now — or use
    Settings -> Server updates (Check now / Update now / Undo).
  - Updates come only from Sealpost's GitHub page, and are installed only
    if they carry Sealpost's signature (your server holds the public key
    to check it). A damaged or changed package is refused and nothing is
    touched.
  - Never changed: config.php, your vault (sealpost-data), and any of
    your own files that aren't part of Sealpost. The files that are
    replaced are backed up first; if anything can't be written, the old
    version is put back by itself. Undo returns to the previous version.
  - Your server checks GitHub at most every 12 hours, and only for the
    version number. It needs PHP's curl, zip and sodium (status.php shows
    "One-click updates: Ready").
  - This one version (1.10.0) has to be uploaded by hand. Updates after it
    are one click.
  - Also: status.php has a "One-click updates" line.

New in 1.10.1
  - Example addresses in this README and in Settings -> Mail accounts
    -> "Send as" now use example.com.
  - Downloads and updates: https://github.com/jeffbristow/sealpost/releases

Quick test after updating (5 minutes)
  [ ] status.php shows all green and "Server version 1.10.1"
  [ ] Sign in; Settings -> Mail accounts -> Edit -> Test connection
      says "Receiving and sending both work"
  [ ] Keys -> Find online… -> your own address finds your key (if you
      published it) or says "No key found" — not an error
  [ ] PGP Tools: encrypt a line to yourself, then Decrypt it
  [ ] Inbox: tick two messages, Mark unread, then Mark read
  [ ] Settings: change "Messages per page", Save; Sealpost on your PC
      shows the same value after its next sync
  [ ] iPhone: Safari -> Share -> Add to Home Screen, open the icon,
      sign in, set a PIN, turn on Face ID; swipe the app away, open it
      again -> Face ID unlocks it

Forgot the vault passphrase?
  It can't be recovered. Your data is still on your PCs: delete the
  folder sealpost-data on the server, then create the vault again from
  a PC with "Set up sync".
