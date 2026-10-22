<?php
/* =====================================================================
 * Sealpost Web — mail.php
 * ---------------------------------------------------------------------
 * The bridge between Sealpost Web (in your browser) and your mail
 * server. Only a signed-in Sealpost device (valid device token) can use
 * it, so it can't be abused as an open relay to other servers.
 *
 * Every request carries the account's connection details. They come
 * from your vault, decrypted in your browser; they're used for this one
 * request's connection and never stored on this server.
 *
 * PGP never happens here: encrypted messages are passed to the browser
 * exactly as they are, and decrypted there with your keys.
 *
 * Sections:
 *   0. Startup + router
 *   1. Account details check
 *   2. folders  — folder tree with unread counts
 *   3. list     — one page of a folder (or search results)
 *   4. message  — the raw message (bytes) for the browser to open
 *   5. flag     — read / unread, flagged
 *   6. move     — move messages to another folder
 *   7. delete   — move to Trash (or delete for good inside Trash)
 *   8. test     — check the connection details
 *   8b. markAllRead — every unread message in a folder becomes read (1.3.0)
 *   8c. smtpTest — can we sign in to the sending server? (1.4.0)
 *   9. send     — hand a finished message to your SMTP server, keep a
 *                 copy in Sent, mark the original answered, remove the
 *                 draft (1.2.0)
 *  10. saveDraft / deleteDraft — drafts in the Drafts folder (1.2.0)
 *      Drafts made by Sealpost Web are encrypted to your own key in the
 *      browser first — the same format Sealpost on your PC uses.
 * ===================================================================== */

declare(strict_types=1);
define('SEALPOST', 1);
require __DIR__ . '/lib.php';
require __DIR__ . '/imap.php';
require __DIR__ . '/smtp.php';

/* =================================================================
 * 0. STARTUP + ROUTER
 * ================================================================= */
ini_set('display_errors', '0');
@set_time_limit(120);
set_exception_handler(function (Throwable $e) {
    if ($e instanceof ImapError) {
        fail(502, 'mail_' . $e->kind, $e->getMessage());
    }
    if ($e instanceof SmtpError) {
        fail(502, 'smtp_' . $e->kind, $e->getMessage());
    }
    error_log('Sealpost mail: ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine());
    fail(500, 'server_error', 'The server had a problem with that request.');
});

require_secure_transport();
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') fail(405, 'post_only', 'Use POST for this request.');
$me = require_auth();

$routes = [
    'folders' => 'mail_folders',
    'list'    => 'mail_list',
    'message' => 'mail_message',
    'flag'    => 'mail_flag',
    'move'    => 'mail_move',
    'delete'  => 'mail_delete',
    'test'    => 'mail_test',
    'markAllRead' => 'mail_mark_all_read',
    'smtpTest'    => 'mail_smtp_test',
    'send'        => 'mail_send',
    'saveDraft'   => 'mail_save_draft',
    'deleteDraft' => 'mail_delete_draft',
    // 1.8.0: folder management
    'createFolder' => 'mail_create_folder',
    'renameFolder' => 'mail_rename_folder',
    'deleteFolder' => 'mail_delete_folder',
];
$action = (string) ($_GET['action'] ?? '');
if (!isset($routes[$action])) fail(404, 'unknown_action', 'Unknown request.');
$routes[$action]();

/* =================================================================
 * 1. ACCOUNT DETAILS CHECK
 *    { host, port, security, username, password, allowSelfSigned }
 * ================================================================= */
function account(?array $given = null): array
{
    $a = $given ?? input('account');
    if (!is_array($a)) fail(400, 'bad_account', 'Missing account details.');
    $host = strtolower(trim((string) ($a['host'] ?? '')));
    if (!preg_match('/^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/', $host)) fail(400, 'bad_account', 'Invalid mail server name.');
    $port = (int) ($a['port'] ?? 993);
    if ($port < 1 || $port > 65535) fail(400, 'bad_account', 'Invalid mail server port.');
    $sec = in_array($a['security'] ?? 'ssl', ['ssl', 'starttls', 'none'], true) ? $a['security'] : 'ssl';
    $user = (string) ($a['username'] ?? '');
    $pass = (string) ($a['password'] ?? '');
    if ($user === '' || strlen($user) > 512 || strlen($pass) > 1024) fail(400, 'bad_account', 'Invalid username or password.');
    return ['host' => $host, 'port' => $port, 'security' => $sec, 'username' => $user, 'password' => $pass, 'allowSelfSigned' => !empty($a['allowSelfSigned'])];
}

function folder_arg(string $name = 'folder'): string
{
    $f = (string) input($name, 'INBOX');
    if ($f === '' || strlen($f) > 1000 || preg_match('/[\r\n\0]/', $f)) fail(400, 'bad_folder', 'Invalid folder.');
    return $f;
}

/** "<a@x> <b@y>" -> ['a@x', 'b@y'] (lower case) — 1.8.0, for conversations */
function msg_ids(string $s): array
{
    preg_match_all('/<([^<>\s]+)>/', $s, $m);
    return array_map('strtolower', $m[1]);
}

/** [3, 7, 9] -> "3,7,9" (only whole numbers accepted) */
function uid_set(): string
{
    $uids = input('uids');
    if (!is_array($uids) || !$uids || count($uids) > 1000) fail(400, 'bad_uids', 'Choose between 1 and 1000 messages.');
    $clean = [];
    foreach ($uids as $u) {
        if (!is_int($u) && !(is_string($u) && ctype_digit($u))) fail(400, 'bad_uids', 'Invalid message number.');
        $n = (int) $u;
        if ($n < 1) fail(400, 'bad_uids', 'Invalid message number.');
        $clean[] = $n;
    }
    return implode(',', array_unique($clean));
}

/* =================================================================
 * 2. FOLDERS
 * ================================================================= */
function mail_folders(): void
{
    $imap = SealpostImap::open(account());
    $folders = $imap->listFolders();
    foreach ($folders as &$f) {
        if (strtoupper($f['path']) === 'INBOX') $f['name'] = 'Inbox';
        // readable full path (folder names with ä, ö, é … arrive encoded) — used for pins, same as Sealpost on your PC
        $f['upath'] = SealpostImap::folderName($f['path']);
        $f['unseen'] = 0;
        $f['total'] = 0;
        if (!$f['noselect']) {
            try {
                $st = $imap->status($f['path'], ['MESSAGES', 'UNSEEN']);
                $f['unseen'] = (int) ($st['UNSEEN'] ?? 0);
                $f['total'] = (int) ($st['MESSAGES'] ?? 0);
            } catch (ImapError $e) { /* leave 0 */ }
        }
        unset($f['flags']);
    }
    unset($f);
    $imap->logout();
    reply(['folders' => folder_tree($folders)]);
}

/**
 * 1.8.0: every folder directly under its parent — Inbox, Drafts, Sent …
 * first (each with its own subfolders), then your folders A–Z, subfolders
 * A–Z under each. Same order as Sealpost on your PC.
 */
function folder_tree(array $items): array
{
    $order = ['\\Inbox' => 0, '\\Drafts' => 1, '\\Sent' => 2, '\\Flagged' => 3, '\\Archive' => 4, '\\Junk' => 5, '\\Trash' => 6];
    $byPath = [];
    foreach ($items as $f) $byPath[$f['path']] = true;
    $parentOf = function (array $f) use ($byPath): ?string {
        $d = $f['delimiter'] ?? null;
        if (!$d) return null;
        $p = $f['path'];
        while (true) {
            $i = strrpos($p, $d);
            if ($i === false || $i === 0) return null;
            $p = substr($p, 0, $i);
            if (isset($byPath[$p])) return $p;
        }
    };
    $kids = []; $roots = [];
    foreach ($items as $f) {
        $p = $parentOf($f);
        if (($f['delimiter'] ?? null) && strtoupper($f['path']) !== 'INBOX') {
            $base = $p !== null ? $p . $f['delimiter'] : '';
            $rel = substr($f['path'], strlen($base));
            $f['name'] = $rel !== '' ? SealpostImap::folderName($rel) : $f['name'];
        }
        if ($p !== null) $kids[$p][] = $f; else $roots[] = $f;
    }
    $byName = fn($a, $b) => strnatcasecmp($a['name'], $b['name']);
    $rank = fn($f) => $order[$f['specialUse'] ?? ''] ?? 50;
    usort($roots, fn($a, $b) => ($rank($a) <=> $rank($b)) ?: $byName($a, $b));
    $out = [];
    $walk = function (array $f, int $depth) use (&$walk, &$out, $kids, $byName) {
        $f['depth'] = $depth;
        $out[] = $f;
        $list = $kids[$f['path']] ?? [];
        usort($list, $byName);
        foreach ($list as $k) $walk($k, $depth + 1);
    };
    foreach ($roots as $r) $walk($r, 0);
    return $out;
}

/* =================================================================
 * 2b. FOLDER MANAGEMENT (1.8.0) — { name } / { from, to } / { folder }
 *     Inbox and the special folders can't be renamed or deleted.
 * ================================================================= */
function folder_name_arg(string $key): string
{
    $f = trim((string) input($key, ''));
    if ($f === '' || strlen($f) > 500 || preg_match('/[\r\n\0]/', $f)) fail(400, 'bad_folder', 'Invalid folder name.');
    return $f;
}
function guard_special(SealpostImap $imap, string $path): void
{
    if (strtoupper($path) === 'INBOX') fail(400, 'special_folder', 'Inbox can\'t be renamed or deleted.');
    foreach ($imap->listFolders() as $f) {
        if ($f['path'] === $path && $f['specialUse']) fail(400, 'special_folder', 'This is one of your mail server\'s special folders (Sent, Drafts, Trash…), so it can\'t be renamed or deleted.');
    }
}
/** parent folder path (as the server spells it) + a new name typed in plain text -> server path */
function child_path(SealpostImap $imap, string $parent, string $name): string
{
    $delim = '/';
    foreach ($imap->listFolders() as $f) {
        if ($f['delimiter'] && ($parent === '' || $f['path'] === $parent)) { $delim = $f['delimiter']; if ($parent !== '') break; }
    }
    if (str_contains($name, $delim)) fail(400, 'bad_folder', "A folder name can't contain \"$delim\" on this server.");
    $enc = preg_match('/[^\x20-\x7e]|&/', $name) ? mb_convert_encoding($name, 'UTF7-IMAP', 'UTF-8') : $name;
    return $parent === '' ? $enc : $parent . $delim . $enc;
}
function mail_create_folder(): void
{
    $name = folder_name_arg('name');
    $parent = trim((string) input('parent', ''));
    $imap = SealpostImap::open(account());
    $imap->createFolderChecked(child_path($imap, $parent, $name));
    $imap->logout();
    reply();
}
/** { from, parent, name } — rename and/or move under another folder ('' = top level) */
function mail_rename_folder(): void
{
    $from = folder_name_arg('from');
    $name = folder_name_arg('name');
    $parent = trim((string) input('parent', ''));
    $imap = SealpostImap::open(account());
    guard_special($imap, $from);
    $to = child_path($imap, $parent, $name);
    if ($to !== $from) $imap->renameFolder($from, $to);
    $imap->logout();
    reply(['path' => $to]);
}
function mail_delete_folder(): void
{
    $path = folder_name_arg('folder');
    $imap = SealpostImap::open(account());
    guard_special($imap, $path);
    $imap->deleteFolder($path);
    $imap->logout();
    reply();
}

/* =================================================================
 * 3. LIST — newest first, one page at a time
 * ================================================================= */
function mail_list(): void
{
    $folder = folder_arg();
    $page = max(0, (int) input('page', 0));
    $size = min(200, max(10, (int) input('pageSize', 50)));
    $search = trim((string) input('search', ''));
    if (mb_strlen($search) > 200) $search = mb_substr($search, 0, 200);

    $imap = SealpostImap::open(account());
    $info = $imap->select($folder, true);
    $uids = $info['exists'] ? $imap->uidSearch($search) : [];
    rsort($uids);
    $total = count($uids);
    $slice = array_slice($uids, $page * $size, $size);

    $rows = [];
    if ($slice) {
        $data = $imap->uidFetch(implode(',', $slice), 'UID FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODY.PEEK[HEADER.FIELDS (CONTENT-TYPE REFERENCES)]');
        foreach ($slice as $uid) {
            if (!isset($data[$uid])) continue;
            $m = $data[$uid];
            $env = is_array($m['ENVELOPE'] ?? null) ? $m['ENVELOPE'] : [];
            $flags = array_map('strtolower', array_map('strval', is_array($m['FLAGS'] ?? null) ? $m['FLAGS'] : []));
            $ctype = '';
            $refs = [];
            foreach ($m as $k => $v) {
                if (!str_starts_with($k, 'BODY[HEADER')) continue;
                $hdr = preg_replace('/\r?\n[ \t]+/', ' ', (string) $v) ?? '';
                if (preg_match('/^content-type:(.*)$/mi', $hdr, $cm)) $ctype = strtolower(trim($cm[1]));
                if (preg_match('/^references:(.*)$/mi', $hdr, $rm)) $refs = msg_ids($rm[1]);   // 1.8.0: conversations
            }
            $ts = isset($env[0]) && $env[0] ? strtotime((string) $env[0]) : false;
            if (!$ts && isset($m['INTERNALDATE'])) $ts = strtotime((string) $m['INTERNALDATE']);
            $rows[] = [
                'uid'        => $uid,
                'subject'    => SealpostImap::decodeHeader($env[1] ?? ''),
                'from'       => SealpostImap::addresses($env[2] ?? null),
                'to'         => SealpostImap::addresses($env[5] ?? null),
                'date'       => $ts ? gmdate('c', $ts) : null,
                'size'       => (int) ($m['RFC822.SIZE'] ?? 0),
                'seen'       => in_array('\\seen', $flags, true),
                'flagged'    => in_array('\\flagged', $flags, true),
                'answered'   => in_array('\\answered', $flags, true),
                'encrypted'  => str_contains($ctype, 'multipart/encrypted'),
                'signed'     => str_contains($ctype, 'multipart/signed'),
                'attachment' => str_contains($ctype, 'multipart/mixed'),
                'messageId'  => msg_ids((string) ($env[9] ?? ''))[0] ?? null,
                'inReplyTo'  => msg_ids((string) ($env[8] ?? ''))[0] ?? null,
                'references' => array_slice($refs, -30),
            ];
        }
    }
    $imap->logout();
    reply(['messages' => $rows, 'total' => $total, 'page' => $page, 'pageSize' => $size, 'hasMore' => ($page + 1) * $size < $total, 'uidValidity' => $info['uidValidity']]);
}

/* =================================================================
 * 4. MESSAGE — raw bytes, exactly as stored on the mail server
 *    (the browser does all MIME + PGP work). Marks it read if asked.
 * ================================================================= */
function mail_message(): void
{
    $folder = folder_arg();
    $uid = (int) input('uid', 0);
    if ($uid < 1) fail(400, 'bad_uids', 'Invalid message number.');
    $markSeen = !empty(input('markSeen'));

    $imap = SealpostImap::open(account());
    $imap->select($folder, !$markSeen);
    $meta = $imap->uidFetch((string) $uid, 'UID RFC822.SIZE FLAGS');
    if (!isset($meta[$uid])) fail(404, 'mail_notfound', 'That message is no longer in this folder.');
    $size = (int) ($meta[$uid]['RFC822.SIZE'] ?? 0);
    if ($size > 40 * 1048576) fail(413, 'too_large', 'This message is larger than 40 MB — open it in Sealpost on your PC.');

    $data = $imap->uidFetch((string) $uid, 'UID BODY.PEEK[]');
    $raw = '';
    foreach ($data[$uid] ?? [] as $k => $v) if ($k === 'BODY[]') $raw = (string) $v;
    $flags = array_map('strtolower', array_map('strval', is_array($meta[$uid]['FLAGS'] ?? null) ? $meta[$uid]['FLAGS'] : []));
    if ($markSeen && !in_array('\\seen', $flags, true)) {
        try { $imap->uidStore((string) $uid, true, ['\\Seen']); $flags[] = '\\seen'; } catch (ImapError $e) { /* read-only folder */ }
    }
    $imap->logout();

    header('Content-Type: application/octet-stream');
    header('Content-Length: ' . strlen($raw));
    header('Cache-Control: no-store, max-age=0');
    header('X-Content-Type-Options: nosniff');
    header('X-Sealpost-Flags: ' . implode(' ', $flags));
    echo $raw;
    exit;
}

/* =================================================================
 * 5. FLAG — { flag: seen | flagged | answered, on: true/false }
 * ================================================================= */
function mail_flag(): void
{
    $map = ['seen' => '\\Seen', 'flagged' => '\\Flagged', 'answered' => '\\Answered'];
    $flag = $map[(string) input('flag', '')] ?? null;
    if (!$flag) fail(400, 'bad_flag', 'Unknown flag.');
    $set = uid_set();
    $imap = SealpostImap::open(account());
    $imap->select(folder_arg(), false);
    $imap->uidStore($set, !empty(input('on')), [$flag]);
    $imap->logout();
    reply();
}

/* =================================================================
 * 6. MOVE — { folder, to, uids }
 * ================================================================= */
function mail_move(): void
{
    $set = uid_set();
    $from = folder_arg();
    $to = folder_arg('to');
    if ($to === $from) reply();
    $imap = SealpostImap::open(account());
    $imap->select($from, false);
    $imap->uidMove($set, $to);
    $imap->logout();
    reply();
}

/* =================================================================
 * 7. DELETE — to Trash; inside Trash (or with no Trash) it's for good
 * ================================================================= */
function mail_delete(): void
{
    $set = uid_set();
    $folder = folder_arg();
    $imap = SealpostImap::open(account());
    $trash = null;
    foreach ($imap->listFolders() as $f) if ($f['specialUse'] === '\\Trash') { $trash = $f['path']; break; }
    $imap->select($folder, false);
    if ($trash && $trash !== $folder) {
        $imap->uidMove($set, $trash);
        $where = 'trash';
    } else {
        $imap->uidStore($set, true, ['\\Deleted']);
        $imap->expunge($set);
        $where = 'gone';
    }
    $imap->logout();
    reply(['result' => $where]);
}

/* =================================================================
 * 8. TEST — can we sign in with these details?
 * ================================================================= */
function mail_test(): void
{
    $imap = SealpostImap::open(account());
    $caps = $imap->caps;
    $imap->logout();
    reply(['ok' => true, 'idle' => in_array('IDLE', $caps, true)]);
}

/* =================================================================
 * 8b. MARK ALL READ — { folder } -> { count }
 * ================================================================= */
function mail_mark_all_read(): void
{
    $imap = SealpostImap::open(account());
    $imap->select(folder_arg(), false);
    $uids = $imap->uidSearchUnseen();
    foreach (array_chunk($uids, 500) as $chunk) $imap->uidStore(implode(',', $chunk), true, ['\\Seen']);
    $imap->logout();
    reply(['count' => count($uids)]);
}

/* =================================================================
 * 8c. SMTP TEST — { account: sending-server details } (1.4.0)
 * ================================================================= */
function mail_smtp_test(): void
{
    $c = SealpostSmtp::open(account());
    $c->quit();
    reply(['ok' => true]);
}

/* =================================================================
 * 9. SEND
 *    Body: the finished message. X-Sealpost-Meta (base64 JSON):
 *    { smtp:{…}, imap:{…}, from, to:[addresses], sentCopy,
 *      replied:{folder,uid}|null, draft:{folder,uid}|null }
 *    Sending must succeed; the follow-up steps are best effort and
 *    reported back as warnings.
 * ================================================================= */
function valid_email(string $e): bool
{
    return (bool) preg_match('/^[^\s<>@"]+@[^\s<>@"]+\.[^\s<>@"]+$/', $e) && strlen($e) <= 320;
}

function mail_send(): void
{
    [$raw, $meta] = read_raw_with_meta(40 * 1048576);
    $smtp = account(is_array($meta['smtp'] ?? null) ? $meta['smtp'] : null);
    $from = trim((string) ($meta['from'] ?? ''));
    $to = array_values(array_unique(array_map(fn($x) => strtolower(trim((string) $x)), is_array($meta['to'] ?? null) ? $meta['to'] : [])));
    if (!valid_email($from)) fail(400, 'bad_from', 'Invalid sender address.');
    if (!$to || count($to) > 200) fail(400, 'bad_rcpt', 'Add between 1 and 200 recipients.');
    foreach ($to as $r) if (!valid_email($r)) fail(400, 'bad_rcpt', 'Invalid recipient address: ' . $r);

    $c = SealpostSmtp::open($smtp);
    $c->send($from, $to, $raw);
    $c->quit();

    // follow-up on the mail (IMAP) side
    $warnings = [];
    $savedToSent = false;
    if (is_array($meta['imap'] ?? null)) {
        try {
            $acc = account($meta['imap']);
            $imap = SealpostImap::open($acc);
            // Gmail and Microsoft 365 file sent mail themselves — avoid a double copy
            $autoSaves = (bool) preg_match('/gmail\.com|googlemail\.com|office365\.com|outlook\.com/i', $acc['host']);
            if (($meta['sentCopy'] ?? true) && !$autoSaves) {
                $sent = $imap->specialFolder('\\Sent');
                if (!$sent) { $imap->createFolder('Sent'); $sent = 'Sent'; }
                $imap->append($sent, $raw, ['\\Seen']);
                $savedToSent = true;
            }
            $rep = $meta['replied'] ?? null;
            if (is_array($rep) && !empty($rep['folder']) && (int) ($rep['uid'] ?? 0) > 0) {
                try { $imap->select((string) $rep['folder'], false); $imap->uidStore((string) (int) $rep['uid'], true, ['\\Answered']); } catch (ImapError $e) { /* message gone */ }
            }
            $dr = $meta['draft'] ?? null;
            if (is_array($dr) && !empty($dr['folder']) && (int) ($dr['uid'] ?? 0) > 0) {
                try { $imap->select((string) $dr['folder'], false); $imap->uidStore((string) (int) $dr['uid'], true, ['\\Deleted']); $imap->expunge((string) (int) $dr['uid']); } catch (ImapError $e) { $warnings[] = 'The draft could not be removed.'; }
            }
            $imap->logout();
        } catch (ImapError $e) {
            $warnings[] = 'Sent, but the copy for your Sent folder could not be saved (' . $e->getMessage() . ')';
        }
    }
    reply(['savedToSent' => $savedToSent, 'warnings' => $warnings]);
}

/* =================================================================
 * 10. DRAFTS
 *    saveDraft body: the finished draft. Meta: { imap:{…}, messageId,
 *    replace:{folder,uid}|null } -> { folder, uid }
 * ================================================================= */
function mail_save_draft(): void
{
    [$raw, $meta] = read_raw_with_meta(40 * 1048576);
    $imap = SealpostImap::open(account(is_array($meta['imap'] ?? null) ? $meta['imap'] : null));
    $folder = $imap->specialFolder('\\Drafts');
    if (!$folder) { $imap->createFolder('Drafts'); $folder = 'Drafts'; }
    $uid = $imap->append($folder, $raw, ['\\Draft', '\\Seen']);
    if (!$uid) {
        $imap->select($folder, true);
        $uid = $imap->findByMessageId((string) ($meta['messageId'] ?? ''));
    }
    // the previous version of this draft is replaced
    $old = $meta['replace'] ?? null;
    if (is_array($old) && !empty($old['folder']) && (int) ($old['uid'] ?? 0) > 0 && !($old['folder'] === $folder && (int) $old['uid'] === $uid)) {
        try { $imap->select((string) $old['folder'], false); $imap->uidStore((string) (int) $old['uid'], true, ['\\Deleted']); $imap->expunge((string) (int) $old['uid']); } catch (ImapError $e) { /* already gone */ }
    }
    $imap->logout();
    reply(['folder' => $folder, 'uid' => $uid]);
}

/** { account, folder, uid } — removes the draft for good (not to Trash). */
function mail_delete_draft(): void
{
    $uid = (int) input('uid', 0);
    if ($uid < 1) fail(400, 'bad_uids', 'Invalid message number.');
    $imap = SealpostImap::open(account());
    $imap->select(folder_arg(), false);
    $imap->uidStore((string) $uid, true, ['\\Deleted']);
    $imap->expunge((string) $uid);
    $imap->logout();
    reply();
}
