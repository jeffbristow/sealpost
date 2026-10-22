<?php
/* =====================================================================
 * Sealpost Web — index.php
 * ---------------------------------------------------------------------
 * The page you open in your browser. It only delivers the app shell
 * (mail, composer, contacts, keys);
 * everything private (your vault, your keys, decrypted mail) is handled
 * by the scripts in web/ inside your browser tab.
 *
 * (The server status page that used to be here is now status.php.)
 *
 * Sections:
 *   1. Security headers (strict Content Security Policy)
 *   2. Page shell: sign-in screen, PIN screen (1.5.0), mail screen,
 *      dialogs
 *
 * 1.5.0: works as an iPhone home-screen app (Safari -> Share -> Add to
 * Home Screen): manifest, icons and the iOS tags in <head>, sw.js.
 * ===================================================================== */

declare(strict_types=1);
define('SEALPOST', 1);
require __DIR__ . '/lib.php';

/* =================================================================
 * 1. SECURITY HEADERS
 *    - scripts only from this folder (no inline scripts, no CDNs)
 *    - connections only back to this server
 *    - remote images allowed at page level only so "Load images" can
 *      work for one message; each email frame adds a stricter policy
 *    - this page can't be put inside another site's frame
 * ================================================================= */
if (cfg('require_https') && !is_https() && !is_localhost()) {
    header('Location: https://' . ($_SERVER['HTTP_HOST'] ?? '') . ($_SERVER['REQUEST_URI'] ?? '/'), true, 301);
    exit;
}
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https: http:; font-src 'self' data:; frame-src 'self' about: blob:; connect-src 'self'; worker-src 'self' blob:; object-src 'none'; base-uri 'self'; form-action 'none'; frame-ancestors 'none'");
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('X-Frame-Options: DENY');
header('Cache-Control: no-store');
header('X-Robots-Tag: noindex, nofollow');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
$v = SEALPOST_SERVER_VERSION;

/* =================================================================
 * 2. PAGE SHELL
 * ================================================================= */
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<meta name="theme-color" content="#121418">
<title>Sealpost</title>
<link rel="icon" href="web/icon.png">
<!-- 1.5.0: iPhone / home-screen app -->
<link rel="manifest" href="manifest.webmanifest">
<link rel="apple-touch-icon" href="web/icons/apple-touch-icon.png">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="mobile-web-app-capable" content="yes">
<!-- 1.9.2: "black", not "black-translucent": iOS 26 leaves a dead strip at the bottom of
     home-screen apps that draw under the status bar (WebKit regression) -->
<meta name="apple-mobile-web-app-status-bar-style" content="black">
<meta name="apple-mobile-web-app-title" content="Sealpost">
<meta name="format-detection" content="telephone=no">
<link rel="stylesheet" href="web/style.css?v=<?= $v ?>">
<script type="module" src="web/app.js?v=<?= $v ?>"></script>
</head>
<body>

<!-- ============================ SIGN-IN SCREEN ============================ -->
<main id="signin" class="signin hidden">
  <form id="signinForm" class="signin-card" autocomplete="on">
    <img src="web/icon.png" alt="" class="signin-icon">
    <h1>Sealpost Web</h1>
    <p class="muted">Sign in with your <b>vault</b> username and passphrase — the same ones you use for "Sync with my web server" in Sealpost.</p>
    <label for="siUser">Vault username</label>
    <input id="siUser" name="username" type="text" autocomplete="username" spellcheck="false" autocapitalize="none" required>
    <label for="siPass">Vault passphrase</label>
    <input id="siPass" name="password" type="password" autocomplete="current-password" required>
    <p id="siErr" class="error" role="alert"></p>
    <button id="siGo" class="btn primary wide" type="submit">Sign in</button>
    <p class="muted small">Your passphrase never leaves this browser. Your mail is decrypted here, not on the server. Closing this tab signs you out.</p>
    <!-- 1.5.0: shown in Safari on an iPhone/iPad until the app is on the home screen -->
    <div id="installHint" class="install-hint hidden">
      <b>Install on this iPhone:</b> tap <span class="share-glyph" aria-label="Share">⬆︎</span> <b>Share</b> at the bottom of Safari, then <b>Add to Home Screen</b>. Open Sealpost from its new icon and sign in there.
    </div>
    <p class="small"><a href="status.php">Server status</a></p>
  </form>
</main>

<!-- ======================== PIN SCREEN (1.5.0) ============================ -->
<main id="pinScreen" class="signin hidden">
  <form id="pinForm" class="signin-card" autocomplete="off">
    <img src="web/icon.png" alt="" class="signin-icon">
    <h1>Sealpost</h1>
    <p id="pinWho" class="muted"></p>
    <!-- 1.6.0: Face ID (shown when it is set up on this phone) -->
    <button id="pinFace" class="btn primary wide face-btn hidden" type="button">🙂 Unlock with Face ID</button>
    <label for="pinInput">PIN</label>
    <input id="pinInput" class="pin-input" type="password" inputmode="numeric" pattern="[0-9]*" maxlength="12" autocomplete="off" required>
    <p id="pinErr" class="error" role="alert"></p>
    <button id="pinGo" class="btn primary wide" type="submit">Unlock</button>
    <button id="pinUsePass" class="btn ghost wide" type="button">Use vault passphrase instead</button>
    <p class="muted small">5 wrong PINs and this device must sign in with the vault passphrase again.</p>
  </form>
</main>

<!-- ============================== MAIL SCREEN ============================= -->
<div id="app" class="hidden">
  <!-- ----- sidebar: accounts + folders ----- -->
  <aside id="sidebar">
    <div class="brand">
      <img src="web/icon.png" alt="" class="brand-icon">
      <span>Sealpost <span class="brand-web">Web</span></span>
      <button id="btnCloseNav" class="icon-btn mobile-only" title="Close">✕</button>
    </div>
    <button id="btnCompose" class="btn primary compose-btn">✎ New message</button>
    <nav id="accountTree" class="account-tree" aria-label="Folders"></nav>
    <div class="nav-bottom">
      <button class="nav-btn active" data-view="mail">✉ Mail</button>
      <button class="nav-btn" data-view="contacts">👥 Contacts</button>
      <button class="nav-btn" data-view="keys">🔑 Keys</button>
      <button class="nav-btn" data-view="tools">🛡 PGP Tools</button>
      <button class="nav-btn" data-view="settings">⚙ Settings</button>
      <div id="userLabel" class="user-label"></div>
      <button id="btnLockApp" class="nav-btn subtle hidden" title="Lock Sealpost — your PIN opens it again">🔐 Lock</button>
      <button id="btnLockKeys" class="nav-btn subtle" title="Forget unlocked private keys in this tab">🔒 Lock keys</button>
      <button id="btnSignOut" class="nav-btn subtle">⎋ Sign out</button>
    </div>
  </aside>
  <div id="navShade" class="nav-shade"></div>

  <!-- ----- message list ----- -->
  <section id="listPane">
    <div class="list-head">
      <div class="list-title">
        <button id="btnNav" class="icon-btn mobile-only" title="Folders">☰</button>
        <span id="folderTitle">Inbox</span> <span id="folderCount" class="muted"></span>
      </div>
      <div class="list-tools">
        <input id="searchBox" type="search" placeholder="Search this folder…" enterkeyhint="search">
        <button id="btnConv" class="icon-btn hidden" title="Group replies into conversations (this account)">💬</button>
        <button id="btnSelectMode" class="icon-btn" title="Select messages (or Ctrl/Shift-click)">☐</button>
        <button id="btnMarkAllRead" class="icon-btn" title="Mark all messages in this folder as read">✓</button>
        <button id="btnRefresh" class="icon-btn" title="Refresh">⟳</button>
        <!-- 1.9.0 (phone): Select / Mark all read / Conversation view / Refresh live in this menu -->
        <button id="btnListMore" class="icon-btn phone-only" title="More" aria-label="More">⋯</button>
      </div>
      <!-- 1.4.0: actions for several selected messages -->
      <div id="bulkBar" class="bulk-bar hidden">
        <span id="bulkCount" class="bulk-count"></span>
        <button class="btn small" data-bulk="read" type="button" title="Mark read">○ Read</button>
        <button class="btn small" data-bulk="unread" type="button" title="Mark unread">● Unread</button>
        <button class="btn small" data-bulk="flag" type="button" title="Flag">⚑</button>
        <select id="bulkMove" class="small-select" aria-label="Move selected to"></select>
        <button class="btn small danger" data-bulk="delete" type="button" title="Delete">🗑</button>
        <span class="spacer"></span>
        <button class="btn small ghost" data-bulk="all" type="button">All</button>
        <button class="icon-btn" data-bulk="clear" type="button" title="Clear selection (Esc)">✕</button>
      </div>
    </div>
    <div id="ptr" class="ptr" aria-hidden="true"><span id="ptrText">↓ Pull to refresh</span></div>
    <div id="messageList" class="message-list" tabindex="0"></div>
    <button id="btnMore" class="btn ghost load-more hidden">Load older messages</button>
  </section>

  <!-- ----- reader ----- -->
  <section id="readerPane">
    <div id="readerEmpty" class="reader-empty"><img src="web/icon.png" alt=""><p>Select a message to read it.</p></div>
    <article id="reader" class="reader hidden">
      <!-- 1.9.0 (phone): Back + ⋯ at the top, actions in a toolbar at the bottom -->
      <div class="phone-topbar phone-only">
        <button id="pBack" class="icon-btn" type="button">‹ Back</button>
        <span class="spacer"></span>
        <button id="pMore" class="icon-btn" type="button" title="More" aria-label="More">⋯</button>
      </div>
      <div class="reader-actions">
        <button id="btnBack" class="btn small mobile-only">← Back</button>
        <button class="btn small primary" data-act="reply">↩ Reply</button>
        <button class="btn small" data-act="replyAll">↩↩ Reply all</button>
        <button class="btn small" data-act="forward">↪ Forward</button>
        <button class="btn small" data-act="unread" title="Mark unread (U)">Mark unread</button>
        <button class="btn small" data-act="flag" title="Flag">⚑ Flag</button>
        <select id="moveSelect" class="small-select" aria-label="Move to folder"></select>
        <button class="btn small" data-act="delete">🗑 Delete</button>
        <button class="btn small" data-act="addContact">👤 Add contact</button>
        <span class="spacer"></span>
        <button class="btn small ghost" data-act="source">Source</button>
      </div>
      <h2 id="rSubject" class="selectable"></h2>
      <div class="meta selectable">
        <div><span class="muted">From</span> <span id="rFrom"></span></div>
        <div><span class="muted">To</span> <span id="rTo"></span></div>
        <div id="rCcRow"><span class="muted">Cc</span> <span id="rCc"></span></div>
        <div><span class="muted">Date</span> <span id="rDate"></span></div>
      </div>
      <div id="pgpBanner"></div>
      <div id="attachments" class="attachments"></div>
      <div class="body-tools">
        <div id="bodyToggle" class="seg hidden"><button class="btn small" data-mode="html">Formatted</button><button class="btn small" data-mode="text">Plain text</button></div>
        <div id="remoteBar" class="remote-bar hidden">Remote images are blocked to protect your privacy. <button id="btnLoadImages" class="btn small">Load images</button></div>
      </div>
      <div class="body-wrap">
        <pre id="textBody" class="text-body selectable"></pre>
        <iframe id="htmlBody" class="hidden" title="Message body" sandbox="allow-popups allow-popups-to-escape-sandbox"></iframe>
      </div>
    </article>
    <nav id="pToolbar" class="phone-toolbar phone-only" aria-label="Message actions">
      <button id="pDelete" type="button"><span class="ico">🗑</span><span>Delete</span></button>
      <button id="pMove" type="button"><span class="ico">📁</span><span>Move</span></button>
      <button id="pFlag" type="button"><span class="ico">⚑</span><span>Flag</span></button>
      <button id="pReply" type="button" class="reply"><span class="ico">↩</span><span>Reply</span></button>
    </nav>
  </section>
  <!-- 1.9.0 (phone): new message, bottom-right where your thumb is -->
  <button id="btnFab" class="fab phone-only" type="button" title="New message" aria-label="New message">✎</button>

  <!-- ----- contacts (1.2.0) ----- -->
  <section id="contactsView" class="side-view">
    <div class="sv-list">
      <div class="list-head">
        <div class="list-title"><button class="icon-btn mobile-only nav-open-btn" title="Menu">☰</button>Contacts <span id="contactCount" class="muted"></span></div>
        <div class="list-tools"><input id="contactFilter" type="search" placeholder="Search contacts…"><button id="btnNewContact" class="btn small primary">+ New</button></div>
      </div>
      <div id="contactList" class="message-list"></div>
    </div>
    <div id="contactDetail" class="sv-detail"></div>
  </section>

  <!-- ----- PGP tools (1.4.0) ----- -->
  <section id="toolsView" class="page-view">
    <div class="page-head"><button class="icon-btn mobile-only nav-open-btn" title="Menu">☰</button><h2>PGP Tools</h2></div>
    <p class="muted page-intro">Encrypt, sign, decrypt or verify text you paste — for messages you write or receive anywhere (chat, web forms, documents). Everything happens in this browser.</p>
    <div class="tools-grid">
      <div class="panel">
        <label for="toolIn">Input</label>
        <textarea id="toolIn" rows="14" spellcheck="false" placeholder="Type or paste text, a PGP message, a signed block, or a public key…"></textarea>
        <div class="row-btns" style="margin-top:6px"><button id="toolPaste" class="btn small" type="button">Paste</button><button id="toolClear" class="btn small ghost" type="button">Clear</button></div>
        <label for="toolRecipients">Recipients (for Encrypt) — email addresses</label>
        <input id="toolRecipients" type="text" placeholder="alice@example.com, bob@example.org" spellcheck="false">
        <label for="toolSigner">Sign with</label>
        <select id="toolSigner"></select>
        <div class="row-btns tool-actions">
          <button id="toolEncrypt" class="btn primary" type="button">🔒 Encrypt</button>
          <button id="toolSign" class="btn" type="button">✍ Sign</button>
          <button id="toolProcess" class="btn" type="button">🔓 Decrypt / Verify / Import</button>
        </div>
      </div>
      <div class="panel">
        <label for="toolOut">Output</label>
        <div id="toolStatus"></div>
        <textarea id="toolOut" rows="18" readonly spellcheck="false"></textarea>
        <div class="row-btns" style="margin-top:6px"><button id="toolCopy" class="btn small" type="button">Copy output</button></div>
      </div>
    </div>
  </section>

  <!-- ----- settings (1.4.0) ----- -->
  <section id="settingsView" class="page-view">
    <div class="page-head"><button class="icon-btn mobile-only nav-open-btn" title="Menu">☰</button><h2>Settings</h2></div>
    <p class="muted page-intro">Saved in your encrypted vault — Sealpost on your PCs uses the same settings and accounts.</p>
    <div class="settings-grid">
      <div class="panel">
        <h3>New messages</h3>
        <label class="check"><input type="checkbox" id="stSign"> Sign messages</label>
        <label class="check"><input type="checkbox" id="stEncrypt"> Encrypt when every recipient has a key</label>
        <label class="check"><input type="checkbox" id="stAttachKey"> Attach my public key</label>
        <label class="check"><input type="checkbox" id="stAutoContacts"> Add people I write to as contacts automatically</label>
        <label for="stFormat">Write new messages in</label>
        <select id="stFormat"><option value="plain">Plain text</option><option value="rich">Rich text (formatting)</option></select>
        <h3>Reading &amp; security</h3>
        <label class="check"><input type="checkbox" id="stRemote"> Load remote images automatically (not recommended)</label>
        <label for="stCache">Keep private keys unlocked for (minutes, 0 = ask every time)</label>
        <input type="text" id="stCache" inputmode="numeric">
        <label for="stPage">Messages per page</label>
        <input type="text" id="stPage" inputmode="numeric">
        <div class="row-btns"><button id="stSave" class="btn primary" type="button">Save settings</button></div>
        <p class="muted small">Settings that belong to one PC (app lock PIN, offline mail, notifications) are changed in Sealpost on that PC.</p>
      </div>
      <div class="panel">
        <div class="row-between"><h3>Mail accounts</h3><button id="stAddAccount" class="btn small primary" type="button">+ Add account</button></div>
        <div id="stAccounts"></div>
        <p class="muted small">Account signatures are edited here too (Edit → Signature).</p>
        <h3>Import a Sealpost backup</h3>
        <p class="muted small">Opens a <b>.sealbackup</b> file in this browser with its backup passphrase and adds its accounts, contacts and keys to your vault — they then sync to your PCs. Nothing already there is deleted.</p>
        <div class="row-btns"><button id="stImportBackup" class="btn" type="button">Choose backup file…</button></div>
        <h3>This device</h3>
        <div id="stDevice"></div>
        <h3>About</h3>
        <p class="small">Sealpost Web <?= htmlspecialchars($v) ?> · <a href="status.php" target="_blank" rel="noopener">Server status</a></p>
      </div>
    </div>
  </section>

  <!-- ----- keys (1.2.0) ----- -->
  <section id="keysView" class="side-view">
    <div class="sv-list">
      <div class="list-head">
        <div class="list-title"><button class="icon-btn mobile-only nav-open-btn" title="Menu">☰</button>Keys <span id="keyCount" class="muted"></span></div>
        <div class="list-tools"><input id="keyFilter" type="search" placeholder="Search keys…"><button id="btnFindKey" class="btn small">Find online…</button><button id="btnImportKey" class="btn small">Import…</button><button id="btnGenerateKey" class="btn small primary">+ New key</button></div>
      </div>
      <div id="keyList" class="message-list"></div>
    </div>
    <div id="keyDetail" class="sv-detail"></div>
  </section>
</div>

<!-- =============================== COMPOSER (1.2.0) ======================= -->
<div id="composeModal" class="modal compose-modal hidden" role="dialog" aria-modal="true" aria-labelledby="composeTitle">
  <div class="modal-card compose-card">
    <div class="modal-head"><h3 id="composeTitle">New message</h3><span id="cDraftStatus" class="muted small draft-status"></span><button id="cSendTop" class="btn primary phone-only" type="button">Send</button><button class="icon-btn" id="cClose" type="button" title="Close">✕</button></div>
    <div class="compose-fields">
      <label for="cFrom">From</label><select id="cFrom"></select>
      <label for="cTo">To</label><div class="to-row"><input id="cTo" class="addr-input" type="text" autocomplete="off" spellcheck="false"><button id="cShowCc" class="btn small ghost" type="button">Cc/Bcc</button></div>
      <div id="cCcRow" class="field-row hidden"><label for="cCc">Cc</label><input id="cCc" class="addr-input" type="text" autocomplete="off" spellcheck="false"></div>
      <div id="cBccRow" class="field-row hidden"><label for="cBcc">Bcc</label><input id="cBcc" class="addr-input" type="text" autocomplete="off" spellcheck="false"></div>
      <label for="cSubject">Subject</label><input id="cSubject" type="text">
    </div>
    <div class="pgp-toggles">
      <label class="toggle"><input type="checkbox" id="cSign"><span>✍ Sign</span></label>
      <label class="toggle"><input type="checkbox" id="cEncrypt"><span>🔒 Encrypt</span></label>
      <label class="toggle"><input type="checkbox" id="cHideSubject"><span>Hide subject</span></label>
      <label class="toggle"><input type="checkbox" id="cAttachKey"><span>Attach my public key</span></label>
      <div id="cKeyStatus" class="key-status"></div>
      <div id="cHint" class="small" style="color:var(--amber)"></div>
    </div>
    <div id="cToolbar" class="editor-bar">
      <label class="toggle small-toggle"><input type="checkbox" id="cRich"><span>Rich text</span></label>
      <div class="tb-group rich-only">
        <button type="button" data-cmd="bold" title="Bold"><b>B</b></button>
        <button type="button" data-cmd="italic" title="Italic"><i>I</i></button>
        <button type="button" data-cmd="underline" title="Underline"><u>U</u></button>
        <button type="button" data-cmd="strikeThrough" title="Strikethrough"><s>S</s></button>
      </div>
      <div class="tb-group rich-only">
        <button type="button" data-cmd="insertUnorderedList" title="Bulleted list">•</button>
        <button type="button" data-cmd="insertOrderedList" title="Numbered list">1.</button>
        <button type="button" data-cmd="quote" title="Quote">❝</button>
        <button type="button" data-cmd="link" title="Link">🔗</button>
        <button type="button" data-cmd="removeFormat" title="Clear formatting">⨯</button>
      </div>
    </div>
    <textarea id="cBody" class="compose-body" spellcheck="true"></textarea>
    <div id="cEditor" class="rich-editor compose-body hidden" contenteditable="true" spellcheck="true"></div>
    <div id="cAttachments" class="chips"></div>
    <div class="modal-foot">
      <button id="cAttach" class="btn" type="button">📎 Attach</button>
      <button id="cDiscard" class="btn ghost danger" type="button">Discard</button>
      <span class="spacer"></span>
      <button id="cSaveDraft" class="btn" type="button">Save draft</button>
      <button id="cSend" class="btn primary" type="button">Send</button>
    </div>
  </div>
</div>
<div id="acBox" class="ac-box hidden"></div>

<!-- ================================ DIALOGS =============================== -->
<div id="passModal" class="modal hidden" role="dialog" aria-modal="true" aria-labelledby="passTitle">
  <div class="modal-card narrow">
    <div class="modal-head"><h3 id="passTitle">Unlock private key</h3></div>
    <p id="passWho" class="muted small"></p>
    <label for="passInput">Key passphrase</label>
    <input id="passInput" type="password" autocomplete="off">
    <p id="passErr" class="error"></p>
    <p class="muted small">The key stays unlocked in this tab for the time set in Sealpost (Settings → Keep private keys unlocked).</p>
    <div class="modal-foot"><span class="spacer"></span><button id="passCancel" class="btn ghost" type="button">Cancel</button><button id="passOk" class="btn primary" type="button">Unlock</button></div>
  </div>
</div>

<div id="dlgModal" class="modal hidden" role="dialog" aria-modal="true" aria-labelledby="dlgTitle">
  <div class="modal-card">
    <div class="modal-head"><h3 id="dlgTitle"></h3><button class="icon-btn" id="dlgX" type="button">✕</button></div>
    <div id="dlgBody"></div>
    <div class="modal-foot"><button id="dlgExtra" class="btn ghost danger hidden" type="button"></button><span class="spacer"></span><button id="dlgCancel" class="btn ghost" type="button">Cancel</button><button id="dlgOk" class="btn primary" type="button">OK</button></div>
  </div>
</div>

<div id="loading" class="loading hidden"><div class="spinner"></div><p id="loadingText">Opening your vault…</p></div>
<div id="toasts" aria-live="polite"></div>
<!-- 1.3.0: right-click menu for messages and folders -->
<div id="ctxMenu" class="ctx-menu hidden" role="menu"></div>
</body>
</html>
