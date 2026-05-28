const CACHE_NAME = 'loyalty-card-v1';
const STATIC_ASSETS = [
  './card.html',
  './manifest.json',
  './logo.png',
  'https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Sans:wght@300;400;500&display=swap',
  'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/dist/umd/supabase.min.js',
  'https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js'
];

// Install — cache all static assets
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      return cache.addAll(STATIC_ASSETS).catch(err => {
        console.log('Cache install partial error:', err);
      });
    })
  );
  self.skipWaiting();
});

// Activate — clean old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// Fetch — cache first for static, network first for Supabase
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // Supabase API calls — network first, fallback to cache
  if (url.hostname.includes('supabase.co')) {
    event.respondWith(
      fetch(event.request.clone())
        .then(response => {
          // Cache successful Supabase responses
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
          }
          return response;
        })
        .catch(() => {
          // Offline — serve cached Supabase response
          return caches.match(event.request).then(cached => {
            if (cached) return cached;
            // Return empty JSON so app doesn't crash
            return new Response(JSON.stringify({ data: null, error: { message: 'Offline' } }), {
              headers: { 'Content-Type': 'application/json' }
            });
          });
        })
    );
    return;
  }

  // Static assets — cache first
  event.respondWith(
    caches.match(event.request).then(cached => {
      if (cached) return cached;
      return fetch(event.request).then(response => {
        if (response.ok) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
        }
        return response;
      }).catch(() => cached || new Response('Offline', { status: 503 }));
    })
  );
});

// Background sync — retry stamp updates when back online
self.addEventListener('sync', event => {
  if (event.tag === 'sync-stamps') {
    event.waitUntil(syncPendingStamps());
  }
});

async function syncPendingStamps() {
  // Placeholder for future offline stamp queue
  console.log('Syncing pending stamps...');
}

// Push notification handler (Phase 3)
self.addEventListener('push', event => {
  if (!event.data) return;
  const data = event.data.json();
  self.registration.showNotification(data.title || 'Loyalty Update', {
    body: data.body || 'You have a new stamp!',
    icon: './logo.png',
    badge: './logo.png',
    data: data
  });
});
