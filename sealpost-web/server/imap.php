<?php
/* =====================================================================
 * Sealpost Web — imap.php
 * ---------------------------------------------------------------------
 * A small, self-contained IMAP client (no PHP imap extension needed —
 * that extension was removed from PHP 8.4).
 *
 * Each web request opens a connection, does its job and logs out.
 * Your mail password arrives with the request from your browser (where
 * it was decrypted from your vault), is used for this one connection,
 * and is never written anywhere on the server.
 *
 * Sections:
 *   1. Errors
 *   2. Connecting (SSL/TLS, STARTTLS) and signing in
 *   3. Sending commands, reading responses (incl. literals)
 *   4. Turning response text into PHP values (tokenizer)
 *   5. Mail commands: folders, status, select, search, fetch, flags, move
 *   6. Helpers: envelope addresses, header decoding, folder names
 * ===================================================================== */

declare(strict_types=1);

if (!defined('SEALPOST')) {
    http_response_code(404);
    exit;
}

/* =================================================================
 * 1. ERRORS
 *    kind: connect | tls | auth | protocol | notfound
 * ================================================================= */
class ImapError extends RuntimeException
{
    public string $kind;
    public function __construct(string $message, string $kind = 'protocol')
    {
        parent::__construct($message);
        $this->kind = $kind;
    }
}

class SealpostImap
{
    /** @var resource|null */
    private $fp = null;
    private int $tagNo = 0;
    public array $caps = [];
    private string $host = '';
    /** literal contents of the response being parsed */
    private array $lits = [];

    /* =================================================================
     * 2. CONNECTING AND SIGNING IN
     *    $acc: host, port, security (ssl|starttls|none), username,
     *          password, allowSelfSigned
     * ================================================================= */
    public static function open(array $acc): self
    {
        $c = new self();
        $c->connect((string) $acc['host'], (int) $acc['port'], (string) $acc['security'], !empty($acc['allowSelfSigned']));
        $c->login((string) $acc['username'], (string) $acc['password']);
        return $c;
    }

    public function connect(string $host, int $port, string $security, bool $allowSelfSigned): void
    {
        $this->host = $host;
        $ctx = stream_context_create(['ssl' => [
            'verify_peer'       => !$allowSelfSigned,
            'verify_peer_name'  => !$allowSelfSigned,
            'allow_self_signed' => $allowSelfSigned,
            'SNI_enabled'       => true,
            'peer_name'         => $host,
        ]]);
        $scheme = $security === 'ssl' ? 'ssl' : 'tcp';
        $errno = 0;
        $errstr = '';
        $warning = '';
        set_error_handler(function ($no, $msg) use (&$warning) { $warning .= ' ' . $msg; return true; });
        $fp = stream_socket_client("$scheme://$host:$port", $errno, $errstr, 15, STREAM_CLIENT_CONNECT, $ctx);
        restore_error_handler();
        if (!$fp) {
            if (stripos($warning, 'certificate verify failed') !== false) {
                throw new ImapError("The mail server's security certificate isn't trusted. If this is a local server (e.g. Proton Bridge), tick \"Accept self-signed certificates\" for this account.", 'tls');
            }
            $why = $errstr ?: 'no answer';
            if (stripos($why, 'certificate') !== false || stripos($why, 'SSL') !== false) {
                throw new ImapError("Secure connection to $host failed ($why).", 'tls');
            }
            throw new ImapError("Can't reach the mail server $host:$port ($why).", 'connect');
        }
        stream_set_timeout($fp, 45);
        $this->fp = $fp;

        $greeting = $this->readLine();
        if (stripos($greeting, '* OK') !== 0 && stripos($greeting, '* PREAUTH') !== 0) {
            throw new ImapError('The mail server did not greet properly.', 'protocol');
        }
        $this->captureCaps($greeting);

        if ($security === 'starttls') {
            $this->simple('STARTTLS');
            $ok = @stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT);
            if ($ok !== true) throw new ImapError("STARTTLS with $host failed.", 'tls');
            $this->caps = [];
        }
    }

    public function login(string $user, string $pass): void
    {
        if (in_array('LOGINDISABLED', $this->caps, true)) {
            throw new ImapError('The mail server refuses sign-in on this connection type. Use SSL/TLS or STARTTLS.', 'auth');
        }
        $r = $this->command(['LOGIN ', $this->astring($user), ' ', $this->astring($pass)], false);
        if ($r['status'] !== 'OK') {
            throw new ImapError('The mail server rejected the username or password' . ($r['text'] ? ' (' . $this->clean($r['text']) . ')' : '') . '.', 'auth');
        }
        $this->captureCaps($r['text']);
        if (!$this->caps) {
            $c = $this->simple('CAPABILITY');
            foreach ($c['untagged'] as $u) if (($u[0] ?? '') === 'CAPABILITY') $this->caps = array_map('strtoupper', array_slice($u, 1));
        }
    }

    public function logout(): void
    {
        if (!$this->fp) return;
        try { $this->command(['LOGOUT']); } catch (Throwable $e) { /* closing anyway */ }
        @fclose($this->fp);
        $this->fp = null;
    }

    public function __destruct()
    {
        if ($this->fp) @fclose($this->fp);
    }

    private function captureCaps(string $text): void
    {
        if (preg_match('/\[CAPABILITY ([^\]]+)\]/i', $text, $m)) {
            $this->caps = array_map('strtoupper', preg_split('/\s+/', trim($m[1])));
        }
    }

    public function has(string $cap): bool
    {
        return in_array(strtoupper($cap), $this->caps, true);
    }

    /* =================================================================
     * 3. COMMANDS AND RESPONSES
     *    A command is a list of pieces; a piece ['lit' => '...'] is sent
     *    as an IMAP literal (for text that can't be quoted).
     *    Returns ['status' => OK|NO|BAD, 'text' => ..., 'untagged' => [tokens...]]
     * ================================================================= */
    private function readLine(): string
    {
        $line = '';
        while (!str_ends_with($line, "\n")) {
            $chunk = fgets($this->fp, 65536);
            if ($chunk === false) {
                $meta = stream_get_meta_data($this->fp);
                throw new ImapError($meta['timed_out'] ?? false ? 'The mail server stopped answering.' : 'The mail server closed the connection.', 'connect');
            }
            $line .= $chunk;
        }
        return $line;
    }

    private function readBytes(int $n): string
    {
        $out = '';
        while (strlen($out) < $n) {
            $chunk = fread($this->fp, min(1048576, $n - strlen($out)));
            if ($chunk === false || $chunk === '') {
                $meta = stream_get_meta_data($this->fp);
                if ($meta['eof'] || $meta['timed_out']) throw new ImapError('The mail server stopped sending.', 'connect');
            }
            $out .= $chunk;
        }
        return $out;
    }

    /** One logical response line with its literals (stored in $this->lits, marked \0Ln\0). */
    private function readResponse(): string
    {
        $text = '';
        for (;;) {
            $line = $this->readLine();
            if (preg_match('/\{(\d+)\+?\}\r?\n$/', $line, $m)) {
                $text .= substr($line, 0, -strlen($m[0]));
                $this->lits[] = $this->readBytes((int) $m[1]);
                $text .= "\0L" . (count($this->lits) - 1) . "\0";
                continue;
            }
            return $text . rtrim($line, "\r\n");
        }
    }

    private function write(string $s): void
    {
        $len = strlen($s);
        for ($done = 0; $done < $len;) {
            $w = fwrite($this->fp, substr($s, $done));
            if ($w === false || $w === 0) throw new ImapError('Lost the connection to the mail server.', 'connect');
            $done += $w;
        }
    }

    public function command(array $pieces, bool $throwOnNo = true): array
    {
        $tag = 'S' . (++$this->tagNo);
        $buf = $tag . ' ';
        $untagged = [];
        foreach ($pieces as $p) {
            if (is_array($p)) {
                $lit = (string) $p['lit'];
                $plus = $this->has('LITERAL+');
                $this->write($buf . '{' . strlen($lit) . ($plus ? '+' : '') . "}\r\n");
                if (!$plus) {
                    // wait for the server's "+ go ahead"
                    for (;;) {
                        $this->lits = [];
                        $l = $this->readResponse();
                        if (str_starts_with($l, '+')) break;
                        if (str_starts_with($l, $tag . ' ')) throw new ImapError('The mail server refused the request.', 'protocol');
                        if (str_starts_with($l, '* ')) $untagged[] = $this->tokenize(substr($l, 2));
                    }
                }
                $buf = $lit;
            } else {
                $buf .= $p;
            }
        }
        $this->write($buf . "\r\n");

        for (;;) {
            $this->lits = [];
            $l = $this->readResponse();
            if (str_starts_with($l, '* ')) {
                $untagged[] = $this->tokenize(substr($l, 2));
                continue;
            }
            if (str_starts_with($l, $tag . ' ')) {
                $rest = substr($l, strlen($tag) + 1);
                $sp = strpos($rest, ' ');
                $status = strtoupper($sp === false ? $rest : substr($rest, 0, $sp));
                $text = $sp === false ? '' : substr($rest, $sp + 1);
                if ($throwOnNo && $status !== 'OK') {
                    throw new ImapError('The mail server said: ' . $this->clean($text), 'protocol');
                }
                return ['status' => $status, 'text' => $text, 'untagged' => $untagged];
            }
            // "+" or anything else outside a literal: ignore
        }
    }

    public function simple(string $cmd): array
    {
        return $this->command([$cmd]);
    }

    /** Quote text for a command, or send it as a literal if it can't be quoted. */
    public function astring(string $s): string|array
    {
        if ($s !== '' && preg_match('/^[\x20-\x7e]*$/', $s)) {
            return '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $s) . '"';
        }
        if ($s === '') return '""';
        return ['lit' => $s];
    }

    private function clean(string $s): string
    {
        return mb_substr(trim(preg_replace('/\0L\d+\0/', '', $s) ?? ''), 0, 200);
    }

    /* =================================================================
     * 4. TOKENIZER
     *    IMAP text -> nested PHP arrays.
     *    atoms / quoted strings / literals -> string, NIL -> null,
     *    ( ... ) -> array. "BODY[HEADER.FIELDS (X)]" stays one atom.
     * ================================================================= */
    private function tokenize(string $s): array
    {
        $pos = 0;
        $out = $this->parseList($s, $pos, false);
        return $out;
    }

    private function parseList(string $s, int &$pos, bool $inner): array
    {
        $items = [];
        $len = strlen($s);
        while ($pos < $len) {
            $ch = $s[$pos];
            if ($ch === ' ') { $pos++; continue; }
            if ($ch === ')') { $pos++; if ($inner) return $items; continue; }
            if ($ch === '(') { $pos++; $items[] = $this->parseList($s, $pos, true); continue; }
            if ($ch === '"') {
                $pos++;
                $str = '';
                while ($pos < $len && $s[$pos] !== '"') {
                    if ($s[$pos] === '\\' && $pos + 1 < $len) $pos++;
                    $str .= $s[$pos++];
                }
                $pos++;
                $items[] = $str;
                continue;
            }
            if ($ch === "\0") {
                $end = strpos($s, "\0", $pos + 1);
                $idx = (int) substr($s, $pos + 2, $end - $pos - 2);
                $items[] = $this->lits[$idx] ?? '';
                $pos = $end + 1;
                continue;
            }
            // atom (brackets may contain spaces and parentheses)
            $start = $pos;
            $depth = 0;
            while ($pos < $len) {
                $c = $s[$pos];
                if ($c === '[') $depth++;
                elseif ($c === ']') $depth--;
                elseif ($depth <= 0 && ($c === ' ' || $c === '(' || $c === ')')) break;
                $pos++;
            }
            $atom = substr($s, $start, $pos - $start);
            $items[] = strtoupper($atom) === 'NIL' ? null : $atom;
        }
        return $items;
    }

    /* =================================================================
     * 5. MAIL COMMANDS
     * ================================================================= */

    /** All folders: [path (server name), name (readable), delimiter, flags[], specialUse] */
    public function listFolders(): array
    {
        $r = $this->simple('LIST "" "*"');
        $out = [];
        foreach ($r['untagged'] as $u) {
            if (self::atom($u[0] ?? null) !== 'LIST') continue;
            $flags = array_map('strval', is_array($u[1] ?? null) ? $u[1] : []);
            $delim = $u[2] ?? null;
            $path = (string) ($u[3] ?? '');
            if ($path === '') continue;
            $out[] = [
                'path'       => $path,
                'name'       => self::folderName($path),
                'delimiter'  => $delim,
                'flags'      => $flags,
                'specialUse' => self::specialUse($path, $flags),
                'noselect'   => (bool) array_intersect(array_map('strtolower', $flags), ['\\noselect', '\\nonexistent']),
            ];
        }
        return $out;
    }

    /** STATUS of one folder, e.g. ['MESSAGES' => 10, 'UNSEEN' => 2] */
    public function status(string $path, array $items = ['MESSAGES', 'UNSEEN']): array
    {
        $r = $this->command(['STATUS ', $this->astring($path), ' (' . implode(' ', $items) . ')'], false);
        $out = [];
        foreach ($r['untagged'] as $u) {
            if (self::atom($u[0] ?? null) === 'STATUS' && is_array(end($u))) {
                $list = end($u);
                for ($i = 0; $i + 1 < count($list); $i += 2) $out[strtoupper((string) $list[$i])] = (int) $list[$i + 1];
            }
        }
        return $out;
    }

    /** Open a folder. Returns ['exists' => n, 'uidValidity' => n] */
    public function select(string $path, bool $readOnly = true): array
    {
        $r = $this->command([$readOnly ? 'EXAMINE ' : 'SELECT ', $this->astring($path)], false);
        if ($r['status'] !== 'OK') throw new ImapError('That folder could not be opened.', 'notfound');
        $info = ['exists' => 0, 'uidValidity' => 0];
        foreach ($r['untagged'] as $u) {
            if (self::atom($u[1] ?? null) === 'EXISTS') $info['exists'] = (int) $u[0];
            foreach ($u as $t) {
                if (is_string($t) && preg_match('/^\[UIDVALIDITY (\d+)\]$/i', $t, $m)) $info['uidValidity'] = (int) $m[1];
            }
        }
        return $info;
    }

    /** UIDs of unread messages in the selected folder (1.3.0). */
    public function uidSearchUnseen(): array
    {
        $r = $this->simple('UID SEARCH UNSEEN');
        $uids = [];
        foreach ($r['untagged'] as $u) {
            if (self::atom($u[0] ?? null) === 'SEARCH') {
                foreach (array_slice($u, 1) as $n) if (is_string($n) && ctype_digit($n)) $uids[] = (int) $n;
            }
        }
        return $uids;
    }

    /** UID SEARCH. $text = '' for all messages, otherwise full-text search. */
    public function uidSearch(string $text = ''): array
    {
        if ($text === '') {
            $r = $this->simple('UID SEARCH ALL');
        } elseif (preg_match('/^[\x20-\x7e]*$/', $text)) {
            $r = $this->command(['UID SEARCH TEXT ', $this->astring($text)]);
        } else {
            $r = $this->command(['UID SEARCH CHARSET UTF-8 TEXT ', ['lit' => $text]], false);
            if ($r['status'] !== 'OK') return [];
        }
        $uids = [];
        foreach ($r['untagged'] as $u) {
            if (self::atom($u[0] ?? null) === 'SEARCH') {
                foreach (array_slice($u, 1) as $n) if (is_string($n) && ctype_digit($n)) $uids[] = (int) $n;
            }
        }
        return $uids;
    }

    /**
     * UID FETCH. Returns [uid => [ITEM => value, ...]]
     * e.g. uidFetch('5:9', 'UID FLAGS ENVELOPE')
     */
    public function uidFetch(string $set, string $items): array
    {
        $r = $this->simple("UID FETCH $set ($items)");
        $out = [];
        foreach ($r['untagged'] as $u) {
            if (self::atom($u[1] ?? null) !== 'FETCH' || !is_array($u[2] ?? null)) continue;
            $list = $u[2];
            $map = [];
            for ($i = 0; $i + 1 < count($list); $i += 2) {
                $map[strtoupper((string) $list[$i])] = $list[$i + 1];
            }
            if (isset($map['UID'])) $out[(int) $map['UID']] = $map;
        }
        return $out;
    }

    /** Add (+) or remove (-) flags on messages. */
    public function uidStore(string $set, bool $add, array $flags): void
    {
        $this->simple('UID STORE ' . $set . ' ' . ($add ? '+' : '-') . 'FLAGS.SILENT (' . implode(' ', $flags) . ')');
    }

    /** Move messages to another folder (MOVE if supported, else copy + delete). */
    public function uidMove(string $set, string $to): void
    {
        if ($this->has('MOVE')) {
            $this->command(['UID MOVE ' . $set . ' ', $this->astring($to)]);
            return;
        }
        $this->command(['UID COPY ' . $set . ' ', $this->astring($to)]);
        $this->uidStore($set, true, ['\\Deleted']);
        $this->expunge($set);
    }

    /** Remove messages marked \Deleted (only the given ones when the server allows). */
    public function expunge(string $set): void
    {
        if ($this->has('UIDPLUS')) $this->simple('UID EXPUNGE ' . $set);
        else $this->simple('EXPUNGE');
    }

    /**
     * Store a finished message in a folder (Sent copy, drafts).
     * Returns its UID when the server reports it (UIDPLUS), else null.
     */
    public function append(string $folder, string $raw, array $flags = ['\\Seen']): ?int
    {
        $raw = preg_replace("/\r?\n/", "\r\n", $raw) ?? $raw;
        $r = $this->command(['APPEND ', $this->astring($folder), ' (' . implode(' ', $flags) . ') ', ['lit' => $raw]]);
        if (preg_match('/\[APPENDUID \d+ (\d+)\]/i', $r['text'], $m)) return (int) $m[1];
        return null;
    }

    /** UID of the message with this Message-ID in the selected folder, or null. */
    public function findByMessageId(string $messageId): ?int
    {
        $id = trim($messageId);
        if ($id === '' || !preg_match('/^<[^\s<>"]+>$/', $id)) return null;
        $r = $this->command(['UID SEARCH HEADER Message-ID ', $this->astring($id)], false);
        $found = null;
        foreach ($r['untagged'] as $u) {
            if (self::atom($u[0] ?? null) === 'SEARCH') foreach (array_slice($u, 1) as $n) if (is_string($n) && ctype_digit($n)) $found = max($found ?? 0, (int) $n);
        }
        return $found;
    }

    /** Create a folder (ignores "already exists"). */
    public function createFolder(string $path): void
    {
        $this->command(['CREATE ', $this->astring($path)], false);
    }

    /** 1.8.0: create a folder and say so if the server refuses (folder management). */
    public function createFolderChecked(string $path): void
    {
        $this->command(['CREATE ', $this->astring($path)]);
        try { $this->command(['SUBSCRIBE ', $this->astring($path)]); } catch (ImapError $e) { /* not every server uses subscriptions */ }
    }

    /** 1.8.0: rename a folder (also how a folder moves under another one). Subfolders go with it. */
    public function renameFolder(string $from, string $to): void
    {
        $this->command(['RENAME ', $this->astring($from), ' ', $this->astring($to)]);
        try { $this->command(['SUBSCRIBE ', $this->astring($to)]); } catch (ImapError $e) { /* ignore */ }
    }

    /** 1.8.0: delete a folder and the messages in it. */
    public function deleteFolder(string $path): void
    {
        try { $this->command(['UNSUBSCRIBE ', $this->astring($path)]); } catch (ImapError $e) { /* ignore */ }
        $this->command(['DELETE ', $this->astring($path)]);
    }

    /** Path of the folder with this special use (\Sent, \Drafts, \Trash …), or null. */
    public function specialFolder(string $use): ?string
    {
        foreach ($this->listFolders() as $f) if ($f['specialUse'] === $use && !$f['noselect']) return $f['path'];
        return null;
    }

    /* =================================================================
     * 6. HELPERS
     * ================================================================= */

    /** Upper-case text of a response word ('' for lists / NIL). */
    private static function atom($t): string
    {
        return is_string($t) ? strtoupper($t) : '';
    }

    /** "&AMQ-rger" (modified UTF-7) -> "Ärger" */
    public static function folderName(string $path): string
    {
        if (strpos($path, '&') === false) return $path;
        $s = @mb_convert_encoding($path, 'UTF-8', 'UTF7-IMAP');
        return is_string($s) && $s !== '' ? $s : $path;
    }

    /** \Sent, \Drafts … from the server, or guessed from common names. */
    public static function specialUse(string $path, array $flags): ?string
    {
        foreach ($flags as $f) {
            $f = ucfirst(strtolower(ltrim((string) $f, '\\')));
            if (in_array($f, ['Sent', 'Drafts', 'Trash', 'Junk', 'Archive', 'All', 'Flagged'], true)) return '\\' . $f;
        }
        if (strtoupper($path) === 'INBOX') return '\\Inbox';
        $leaf = strtolower(preg_replace('/^.*[\/.]/', '', $path) ?? $path);
        $guess = [
            'sent' => '\\Sent', 'sent items' => '\\Sent', 'sent mail' => '\\Sent', 'sent messages' => '\\Sent',
            'drafts' => '\\Drafts', 'draft' => '\\Drafts',
            'trash' => '\\Trash', 'deleted items' => '\\Trash', 'deleted messages' => '\\Trash', 'bin' => '\\Trash',
            'spam' => '\\Junk', 'junk' => '\\Junk', 'junk email' => '\\Junk', 'bulk mail' => '\\Junk',
            'archive' => '\\Archive', 'archives' => '\\Archive',
        ];
        return $guess[$leaf] ?? null;
    }

    /** RFC 2047 "=?UTF-8?B?…?=" -> readable UTF-8; repairs non-UTF-8 bytes. */
    public static function decodeHeader(?string $s): string
    {
        if ($s === null || $s === '') return '';
        if (strpos($s, '=?') !== false) {
            $d = @iconv_mime_decode($s, ICONV_MIME_DECODE_CONTINUE_ON_ERROR, 'UTF-8');
            if ($d === false || $d === '') $d = @mb_decode_mimeheader($s);
            if (is_string($d)) $s = $d;
        }
        if (!mb_check_encoding($s, 'UTF-8')) $s = mb_convert_encoding($s, 'UTF-8', 'Windows-1252');
        return $s;
    }

    /** ENVELOPE address list -> [['name' => …, 'address' => …], …] */
    public static function addresses($list): array
    {
        if (!is_array($list)) return [];
        $out = [];
        foreach ($list as $a) {
            if (!is_array($a) || count($a) < 4) continue;
            if ($a[2] === null || $a[3] === null) continue; // group markers
            $out[] = ['name' => self::decodeHeader($a[0]), 'address' => strtolower($a[2] . '@' . $a[3])];
        }
        return $out;
    }
}
