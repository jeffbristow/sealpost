# Sealpost

PGP email: a desktop IMAP/SMTP client with OpenPGP built in, plus a
self-hosted sync server and webmail (Sealpost Web) that also installs on an
iPhone home screen. Your accounts, contacts and keys sync between them through
a zero-knowledge, end-to-end encrypted vault on your own website.

| Folder | What |
|--------|------|
| [`sealpost/`](sealpost/) | Desktop app (Electron; Windows installer, Linux AppImage/.deb). See its [README](sealpost/README.md). |
| [`sealpost-web/server/`](sealpost-web/server/) | Sync server + Sealpost Web (PHP 8 + SQLite, no database server needed). See [README.txt](sealpost-web/server/README.txt). |
| [`sealpost-web/sealpost-check.php`](sealpost-web/sealpost-check.php) | Upload alone to check whether a host can run the server. |

## Quick start (development)

```bash
cd sealpost
npm install
npm test      # PHP on PATH (with pdo_sqlite) also runs the sync-server tests
npm start
```

## Installing the server

1. Upload the contents of `sealpost-web/server/` to a folder on your site.
2. Copy `config.example.php` to `config.php` and set your own `setup_code`.
3. Open `status.php` in that folder; every line should be green.
4. In Sealpost on your PC: Settings → Sync with my web server → Set up sync.

See [CLAUDE.md](CLAUDE.md) for the architecture and development notes.
