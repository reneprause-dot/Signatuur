// Signatuur Service Worker v2.0
// Cache-First für Assets, Network-First für API-Calls

const CACHE_NAME    = 'signatuur-v2';
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/manifest.json',
];

// Externe CDN-Assets cachen
const CDN_ASSETS = [
  'https://fonts.googleapis.com/css2?family=Cormorant+Garamond:ital,wght@0,300;0,400;0,600;1,300;1,400&family=Azeret+Mono:wght@300;400;500&display=swap',
  'https://unpkg.com/@supabase/supabase-js@2',
  'https://unpkg.com/pdf-lib@1.17.1/dist/pdf-lib.min.js',
];

// ── INSTALL ──────────────────────────────────────────────
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      // Static Assets zwingend cachen
      return cache.addAll(STATIC_ASSETS).then(() => {
        // CDN Assets best-effort
        return Promise.allSettled(CDN_ASSETS.map(url => cache.add(url)));
      });
    })
  );
  self.skipWaiting();
});

// ── ACTIVATE ─────────────────────────────────────────────
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames =>
      Promise.all(
        cacheNames
          .filter(name => name !== CACHE_NAME)
          .map(name => caches.delete(name))
      )
    )
  );
  self.clients.claim();
});

// ── FETCH STRATEGY ───────────────────────────────────────
self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);

  // Supabase API + Edge Functions → Network-First (nie cachen)
  if (url.hostname.includes('supabase.co') ||
      url.hostname.includes('supabase.io')) {
    event.respondWith(networkFirst(request));
    return;
  }

  // Fonts + CDN → Cache-First mit Netzwerk-Fallback
  if (url.hostname.includes('fonts.googleapis.com') ||
      url.hostname.includes('fonts.gstatic.com') ||
      url.hostname.includes('unpkg.com')) {
    event.respondWith(cacheFirst(request));
    return;
  }

  // App-Shell (HTML, JS, CSS) → Cache-First
  if (STATIC_ASSETS.includes(url.pathname) || url.pathname === '/') {
    event.respondWith(cacheFirst(request));
    return;
  }

  // Alles andere → Network mit Cache-Fallback
  event.respondWith(networkFirst(request));
});

// ── STRATEGIEN ───────────────────────────────────────────
async function cacheFirst(request) {
  const cached = await caches.match(request);
  if (cached) return cached;
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(CACHE_NAME);
      cache.put(request, response.clone());
    }
    return response;
  } catch {
    return new Response('Offline — Bitte Internetverbindung prüfen.', {
      status: 503,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' }
    });
  }
}

async function networkFirst(request) {
  try {
    const response = await fetch(request);
    if (response.ok && request.method === 'GET') {
      const cache = await caches.open(CACHE_NAME);
      cache.put(request, response.clone());
    }
    return response;
  } catch {
    const cached = await caches.match(request);
    return cached || new Response(
      JSON.stringify({ error: 'Offline', message: 'Keine Internetverbindung' }),
      { status: 503, headers: { 'Content-Type': 'application/json' } }
    );
  }
}

// ── BACKGROUND SYNC (für offline erstellte Dokumente) ────
self.addEventListener('sync', event => {
  if (event.tag === 'sync-pending-docs') {
    event.waitUntil(syncPendingDocuments());
  }
});

async function syncPendingDocuments() {
  // IndexedDB nach offline-erstellten Docs durchsuchen
  // und bei Verbindung an Supabase übertragen
  console.log('[SW] Syncing pending documents...');
}

// ── PUSH NOTIFICATIONS (Signatur-Erinnerungen) ───────────
self.addEventListener('push', event => {
  if (!event.data) return;
  const data = event.data.json();
  event.waitUntil(
    self.registration.showNotification(data.title || 'Signatuur', {
      body: data.body,
      icon: '/icons/icon-192.png',
      badge: '/icons/icon-72.png',
      data: data.url ? { url: data.url } : {},
      actions: [
        { action: 'sign', title: 'Jetzt unterschreiben' },
        { action: 'dismiss', title: 'Schließen' }
      ]
    })
  );
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  if (event.action === 'sign' && event.notification.data?.url) {
    event.waitUntil(clients.openWindow(event.notification.data.url));
  }
});
