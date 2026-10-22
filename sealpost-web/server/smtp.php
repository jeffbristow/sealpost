<?php
/* =====================================================================
 * Sealpost Web — smtp.php
 * ---------------------------------------------------------------------
 * A small SMTP client for sending mail (no PHP extensions needed).
 * Sealpost Web builds the complete message — including any PGP
 * signing/encryption — in your browser; this only hands the finished
 * bytes to your mail provider's SMTP server, exactly as they are.
 *
 * Sections:
 *   1. Errors
 *   2. Connecting (SSL/TLS, STARTTLS), EHLO, sign-in (PLAIN / LOGIN)
 *   3. Sending one message (MAIL FROM, RCPT TO, DATA)
 *   4. Reading replies
 * ===================================================================== */

declare(strict_types=1);

if (!defined('SEALPOST')) {
    http_response_code(404);
    exit;
}

/* =================================================================
 * 1. ERRORS — kind: connect | tls | auth | rejected | protocol
 * ================================================================= */
class SmtpError extends RuntimeException
{
    public string $kind;
    public function __construct(string $message, string $kind = 'protocol')
    {
        parent::__construct($message);
        $this->kind = $kind;
    }
}

class SealpostSmtp
{
    /** @var resource|null */
    private $fp = null;
    private array $ext = [];   // EHLO extensions, e.g. ['AUTH' => 'PLAIN LOGIN', 'SIZE' => '...']
    private string $host = '';

    /* =================================================================
     * 2. CONNECT + SIGN IN
     *    $acc: host, port, security (ssl|starttls|none), username,
     *          password, allowSelfSigned
     * ================================================================= */
    public static function open(array $acc): self
    {
        $c = new self();
        $c->connect((string) $acc['host'], (int) $acc['port'], (string) $acc['security'], !empty($acc['allowSelfSigned']));
        if ((string) $acc['username'] !== '') $c->auth((string) $acc['username'], (string) $acc['password']);
        return $c;
    }

    public function connect(string $host, int $port, string $security, bool $allowSelfSigned): void
    {
        $this->host = $host;
        $ctx = stream_context_create(['ssl' => [
            'verify_peer' => !$allowSelfSigned, 'verify_peer_name' => !$allowSelfSigned,
            'allow_self_signed' => $allowSelfSigned, 'SNI_enabled' => true, 'peer_name' => $host,
        ]]);
        $warning = '';
        set_error_handler(function ($no, $msg) use (&$warning) { $warning .= ' ' . $msg; return true; });
        $fp = stream_socket_client(($security === 'ssl' ? 'ssl' : 'tcp') . "://$host:$port", $errno, $errstr, 15, STREAM_CLIENT_CONNECT, $ctx);
        restore_error_handler();
        if (!$fp) {
            if (stripos($warning, 'certificate verify failed') !== false) {
                throw new SmtpError("The sending server's security certificate isn't trusted. For a local server (e.g. Proton Bridge) tick \"Accept self-signed certificates\" for this account in Sealpost.", 'tls');
            }
            throw new SmtpError("Can't reach the sending server $host:$port (" . ($errstr ?: 'no answer') . ').', 'connect');
        }
        stream_set_timeout($fp, 60);
        $this->fp = $fp;
        $this->expect([220], 'The sending server did not greet properly');
        $this->ehlo();
        if ($security === 'starttls') {
            if (!isset($this->ext['STARTTLS'])) throw new SmtpError("$host doesn't offer STARTTLS on port $port.", 'tls');
            $this->cmd('STARTTLS', [220]);
            if (@stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT) !== true) {
                throw new SmtpError("STARTTLS with $host failed.", 'tls');
            }
            $this->ehlo();
        }
    }

    private function ehlo(): void
    {
        $name = preg_replace('/[^A-Za-z0-9.-]/', '', (string) ($_SERVER['SERVER_NAME'] ?? 'localhost')) ?: 'localhost';
        $this->write("EHLO $name\r\n");
        [$code, $lines] = $this->reply();
        if ($code !== 250) {
            $this->write("HELO $name\r\n");
            $this->expectReply([250], 'The sending server refused the greeting');
            $this->ext = [];
            return;
        }
        $this->ext = [];
        foreach (array_slice($lines, 1) as $l) {
            $parts = explode(' ', trim($l), 2);
            $this->ext[strtoupper($parts[0])] = $parts[1] ?? '';
        }
    }

    public function auth(string $user, string $pass): void
    {
        $methods = strtoupper($this->ext['AUTH'] ?? '');
        if ($methods === '') return; // server doesn't want a sign-in
        if (str_contains($methods, 'PLAIN')) {
            $this->write('AUTH PLAIN ' . base64_encode("\0$user\0$pass") . "\r\n");
        } elseif (str_contains($methods, 'LOGIN')) {
            $this->cmd('AUTH LOGIN', [334]);
            $this->cmd(base64_encode($user), [334]);
            $this->write(base64_encode($pass) . "\r\n");
        } else {
            throw new SmtpError('The sending server only offers sign-in methods Sealpost Web does not support (' . $methods . ').', 'auth');
        }
        [$code, $lines] = $this->reply();
        if ($code !== 235) throw new SmtpError('The sending server rejected the username or password (' . $this->clean($lines) . ').', 'auth');
    }

    /* =================================================================
     * 3. SEND — $raw is the finished message (CRLF line endings)
     *    Returns the server's final answer text.
     * ================================================================= */
    public function send(string $from, array $rcpts, string $raw): string
    {
        $size = isset($this->ext['SIZE']) ? ' SIZE=' . strlen($raw) : '';
        $this->cmd('MAIL FROM:<' . $from . '>' . $size, [250], 'rejected');
        $refused = [];
        foreach ($rcpts as $r) {
            $this->write('RCPT TO:<' . $r . ">\r\n");
            [$code, $lines] = $this->reply();
            if ($code !== 250 && $code !== 251) $refused[] = $r . ': ' . $this->clean($lines);
        }
        if ($refused) {
            try { $this->cmd('RSET', [250]); } catch (Throwable $e) { /* closing anyway */ }
            throw new SmtpError('The sending server refused: ' . implode('; ', $refused), 'rejected');
        }
        $this->cmd('DATA', [354], 'rejected');
        // normalise line endings and "dot-stuff" lines starting with a dot
        $data = preg_replace("/\r?\n/", "\r\n", $raw) ?? $raw;
        if (!str_ends_with($data, "\r\n")) $data .= "\r\n";
        $data = preg_replace('/^\./m', '..', $data) ?? $data;
        for ($i = 0, $n = strlen($data); $i < $n; $i += 65536) $this->write(substr($data, $i, 65536));
        $this->write(".\r\n");
        [$code, $lines] = $this->reply();
        if ($code !== 250) throw new SmtpError('The sending server did not accept the message (' . $this->clean($lines) . ').', 'rejected');
        return $this->clean($lines);
    }

    public function quit(): void
    {
        if (!$this->fp) return;
        try { $this->write("QUIT\r\n"); $this->reply(); } catch (Throwable $e) { /* ignore */ }
        @fclose($this->fp);
        $this->fp = null;
    }

    public function __destruct()
    {
        if ($this->fp) @fclose($this->fp);
    }

    /* =================================================================
     * 4. REPLIES
     * ================================================================= */
    private function write(string $s): void
    {
        for ($done = 0, $len = strlen($s); $done < $len;) {
            $w = fwrite($this->fp, substr($s, $done));
            if ($w === false || $w === 0) throw new SmtpError('Lost the connection to the sending server.', 'connect');
            $done += $w;
        }
    }

    /** [code, [lines...]] — multi-line replies ("250-...") are collected. */
    private function reply(): array
    {
        $lines = [];
        for (;;) {
            $l = fgets($this->fp, 8192);
            if ($l === false) throw new SmtpError('The sending server stopped answering.', 'connect');
            $lines[] = rtrim(substr($l, 4), "\r\n");
            if (strlen($l) < 4 || $l[3] !== '-') return [(int) substr($l, 0, 3), $lines];
        }
    }

    private function cmd(string $line, array $ok, string $kind = 'protocol'): array
    {
        $this->write($line . "\r\n");
        return $this->expectReply($ok, 'The sending server said', $kind);
    }

    private function expect(array $ok, string $what): void
    {
        $this->expectReply($ok, $what);
    }

    private function expectReply(array $ok, string $what, string $kind = 'protocol'): array
    {
        [$code, $lines] = $this->reply();
        if (!in_array($code, $ok, true)) throw new SmtpError($what . ': ' . $code . ' ' . $this->clean($lines), $kind);
        return [$code, $lines];
    }

    private function clean(array $lines): string
    {
        return mb_substr(trim(implode(' ', $lines)), 0, 300);
    }
}
