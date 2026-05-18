const CACHE_VERSION = 'v4';
const STATIC_CACHE  = 'art-static-' + CACHE_VERSION;
const PAGES_CACHE   = 'art-pages-'  + CACHE_VERSION;

// Ressources à pré-charger dès l'installation
const PRECACHE = [
  '/offline',
  '/static/logo.png',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png',
  'https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css',
  'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css',
  'https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js',
];

// ── Installation ──────────────────────────────────────────────────────────────
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then(cache => cache.addAll(PRECACHE))
      .then(() => self.skipWaiting())
  );
});

// ── Keep-alive : empêche Render de mettre l'app en veille pendant utilisation ──
self.addEventListener('activate', event => {
  const keep = [STATIC_CACHE, PAGES_CACHE];
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(k => !keep.includes(k)).map(k => caches.delete(k))
      ))
      .then(() => self.clients.claim())
      .then(() => {
        // Ping toutes les 10 min pour maintenir le serveur actif
        setInterval(() => fetch('/ping', { cache: 'no-store' }).catch(() => {}), 10 * 60 * 1000);
      })
  );
});

// ── Stratégie de cache ────────────────────────────────────────────────────────
self.addEventListener('fetch', event => {
  const req = event.request;
  const url = new URL(req.url);

  // On ne gère que les GET
  if (req.method !== 'GET') return;
  if (!url.protocol.startsWith('http')) return;

  // 1. CDN (Bootstrap, icons) → Cache-First
  if (url.hostname.includes('jsdelivr.net')) {
    event.respondWith(cacheFirst(req, STATIC_CACHE));
    return;
  }

  // 2. Fichiers statiques locaux → Cache-First
  if (url.pathname.startsWith('/static/')) {
    event.respondWith(cacheFirst(req, STATIC_CACHE));
    return;
  }

  // 3. API JSON → Network-Only (données toujours fraîches)
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(fetch(req));
    return;
  }

  // 4. Pages HTML → Network-First avec fallback cache puis offline
  event.respondWith(networkFirst(req));
});

// ── Helpers ───────────────────────────────────────────────────────────────────
async function cacheFirst(req, cacheName) {
  const cached = await caches.match(req);
  if (cached) return cached;
  try {
    const resp = await fetch(req);
    if (resp.ok) {
      const cache = await caches.open(cacheName);
      cache.put(req, resp.clone());
    }
    return resp;
  } catch {
    return new Response('Ressource indisponible', { status: 503 });
  }
}

async function networkFirst(req) {
  try {
    const resp = await fetch(req);
    if (resp.ok) {
      const cache = await caches.open(PAGES_CACHE);
      cache.put(req, resp.clone());
    }
    return resp;
  } catch {
    const cached = await caches.match(req);
    if (cached) return cached;
    // Fallback : page offline
    const offline = await caches.match('/offline');
    return offline || new Response('<h2>Hors ligne</h2>', {
      headers: { 'Content-Type': 'text/html' }
    });
  }
}
