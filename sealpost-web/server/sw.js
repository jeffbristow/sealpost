/* =====================================================================
 * Sealpost Web — sw.js  (service worker, added 1.5.0)
 * ---------------------------------------------------------------------
 * Lets Sealpost start like an app from the iPhone home screen, even on
 * a weak connection. It keeps ONLY the app itself (page, scripts,
 * styles, icons) — never your mail, your vault or anything from
 * api.php / mail.php / keys.php / update.php. Those always go straight to the server.
 *
 * Strategy: always try the network first (so updates show up at once);
 * use the saved copy only when the network can't be reached.
 *
 * Sections:
 *   1. What may be kept
 *   2. Install / activate (old copies are removed)
 *   3. Fetch: network first, saved copy when offline
 * ===================================================================== */

/* =================================================================
 * 1. WHAT MAY BE KEPT
 * ================================================================= */
const CACHE = 'sealpost-shell-1.10.1';
const SHELL = ['./', 'manifest.webmanifest', 'web/icon.png', 'web/icons/apple-touch-icon.png'];

function mayKeep(url, request) {
  if (request.method !== 'GET' || url.origin !== self.location.origin) return false;
  const p = url.pathname;
  if (/\/(api|mail|keys|status|update)\.php$/i.test(p)) return false;   // private data: never (update.php: 1.10.0)
  if (request.mode === 'navigate') return true;                        // the page itself
  return /\/web\/.+\.(js|css|png|svg|woff2?)$/i.test(p) || /manifest\.webmanifest$/.test(p);
}

/* =================================================================
 * 2. INSTALL / ACTIVATE
 * ================================================================= */
self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).catch(() => {}).then(() => self.skipWaiting()));
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k.startsWith('sealpost-shell-') && k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

/* =================================================================
 * 3. FETCH — network first, saved copy only when offline
 * ================================================================= */
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (!mayKeep(url, e.request)) return;                 // let the browser handle it normally
  e.respondWith((async () => {
    const cache = await caches.open(CACHE);
    try {
      // page: as normal; scripts/styles: always ask the server whether there is a newer copy
      const res = await (e.request.mode === 'navigate' ? fetch(e.request) : fetch(e.request, { cache: 'no-cache' }));
      if (res.ok && res.type === 'basic') cache.put(e.request.mode === 'navigate' ? './' : e.request, res.clone()).catch(() => {});
      return res;
    } catch {
      const hit = await cache.match(e.request.mode === 'navigate' ? './' : e.request);
      if (hit) return hit;
      return new Response('<!doctype html><meta name="viewport" content="width=device-width"><body style="background:#121418;color:#e6e8ec;font:16px system-ui;padding:40px 20px;text-align:center"><h2>Sealpost</h2><p>No connection to your server right now.</p><p><button onclick="location.reload()">Try again</button></p>',
        { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }
  })());
});
