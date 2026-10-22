// Test SMTP server: SSL on 11465, STARTTLS on 11587. Saves each message to OUT dir.
const { SMTPServer } = require('/home/claude/webtools/node_modules/smtp-server');
const fs = require('fs'); const path = require('path');
const OUT = process.argv[2]; fs.mkdirSync(OUT, { recursive: true });
const key = fs.readFileSync('/tmp/claude-0/-home-claude/9dd9b99b-d7e1-5caf-8891-fa8183489961/scratchpad/dovecot/key.pem'), cert = fs.readFileSync('/tmp/claude-0/-home-claude/9dd9b99b-d7e1-5caf-8891-fa8183489961/scratchpad/dovecot/cert.pem');
let n = 0;
const opts = secure => ({
  secure, key, cert, authMethods: ['PLAIN', 'LOGIN'], size: 50 * 1024 * 1024,
  onAuth(a, s, cb) { if (a.username === 'jeff@test.local' && a.password === 'mailpass123') cb(null, { user: a.username }); else cb(new Error('Invalid username or password')); },
  onRcptTo(addr, s, cb) { if (addr.address.startsWith('reject')) cb(new Error('No such user')); else cb(); },
  onData(stream, s, cb) { const chunks = []; stream.on('data', c => chunks.push(c)); stream.on('end', () => { const f = path.join(OUT, String(++n).padStart(3, '0') + '.eml'); fs.writeFileSync(f, Buffer.concat(chunks)); fs.writeFileSync(f + '.json', JSON.stringify({ from: s.envelope.mailFrom.address, to: s.envelope.rcptTo.map(r => r.address) })); cb(); }); }
});
new SMTPServer(opts(true)).listen(11465, '127.0.0.1');
new SMTPServer(opts(false)).listen(11587, '127.0.0.1');
console.log('smtpd ready');
