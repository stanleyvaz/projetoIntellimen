// Service Worker para IntelliMen PWA
const CACHE_NAME = 'intellimen-v1.0.0';
const STATIC_CACHE_NAME = 'intellimen-static-v1.0.0';
const DYNAMIC_CACHE_NAME = 'intellimen-dynamic-v1.0.0';

// Arquivos para cache estático (sempre em cache)
const STATIC_FILES = [
  '/',
  '/manifest.json',
  '/icon-192x192.png',
  '/icon-512x512.png',
  // Fontes do Google
  'https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap',
  'https://fonts.gstatic.com/s/inter/v12/UcCO3FwrK3iLTeHuS_fvQtMwCp50KnMw2boKoduKmMEVuLyfAZ9hiJ-Ek-_EeA.woff2'
];

// Arquivos para cache dinâmico (cache conforme uso)
const DYNAMIC_FILES = [
  '/api/user',
  '/api/progress',
  '/api/stats'
];

// Instalação do Service Worker
self.addEventListener('install', event => {
  console.log('🔧 Service Worker: Instalando...');
  
  event.waitUntil(
    Promise.all([
      // Cache estático
      caches.open(STATIC_CACHE_NAME).then(cache => {
        console.log('📦 Service Worker: Cacheando arquivos estáticos');
        return cache.addAll(STATIC_FILES.map(url => new Request(url, { cache: 'reload' })));
      }),
      // Cache dinâmico vazio
      caches.open(DYNAMIC_CACHE_NAME).then(cache => {
        console.log('🗂️ Service Worker: Cache dinâmico criado');
        return Promise.resolve();
      })
    ]).then(() => {
      console.log('✅ Service Worker: Instalação concluída');
      // Force activation
      return self.skipWaiting();
    })
  );
});

// Ativação do Service Worker
self.addEventListener('activate', event => {
  console.log('🚀 Service Worker: Ativando...');
  
  event.waitUntil(
    // Limpar caches antigos
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames
          .filter(cacheName => 
            cacheName.startsWith('intellimen-') && 
            cacheName !== STATIC_CACHE_NAME && 
            cacheName !== DYNAMIC_CACHE_NAME
          )
          .map(cacheName => {
            console.log('🗑️ Service Worker: Removendo cache antigo:', cacheName);
            return caches.delete(cacheName);
          })
      );
    }).then(() => {
      console.log('✅ Service Worker: Ativação concluída');
      // Take control of all pages
      return self.clients.claim();
    })
  );
});

// Interceptação de requisições (Fetch)
self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);

  // Ignorar requisições não HTTP/HTTPS
  if (!request.url.startsWith('http')) {
    return;
  }

  // Estratégia para diferentes tipos de requisições
  if (url.pathname.startsWith('/api/')) {
    // API: Network First (sempre tentar rede primeiro)
    event.respondWith(networkFirstStrategy(request));
  } else if (STATIC_FILES.some(file => url.pathname === file || url.href === file)) {
    // Arquivos estáticos: Cache First
    event.respondWith(cacheFirstStrategy(request, STATIC_CACHE_NAME));
  } else if (url.pathname === '/' || url.pathname.endsWith('.html')) {
    // HTML: Network First com fallback
    event.respondWith(networkFirstWithFallback(request));
  } else {
    // Outros recursos: Stale While Revalidate
    event.respondWith(staleWhileRevalidateStrategy(request));
  }
});

// Estratégia Cache First (cache primeiro, rede como fallback)
async function cacheFirstStrategy(request, cacheName) {
  try {
    const cache = await caches.open(cacheName);
    const cachedResponse = await cache.match(request);
    
    if (cachedResponse) {
      // Retorna do cache
      return cachedResponse;
    }
    
    // Se não estiver em cache, busca na rede
    const networkResponse = await fetch(request);
    
    // Cacheia a resposta para próximas vezes
    if (networkResponse.status === 200) {
      cache.put(request, networkResponse.clone());
    }
    
    return networkResponse;
  } catch (error) {
    console.error('❌ Cache First Error:', error);
    return new Response('Offline - Conteúdo não disponível', { 
      status: 503,
      statusText: 'Service Unavailable'
    });
  }
}

// Estratégia Network First (rede primeiro, cache como fallback)
async function networkFirstStrategy(request) {
  try {
    const networkResponse = await fetch(request);
    
    // Se a resposta for OK, cacheia
    if (networkResponse.status === 200) {
      const cache = await caches.open(DYNAMIC_CACHE_NAME);
      cache.put(request, networkResponse.clone());
    }
    
    return networkResponse;
  } catch (error) {
    // Se a rede falhar, tenta o cache
    const cache = await caches.open(DYNAMIC_CACHE_NAME);
    const cachedResponse = await cache.match(request);
    
    if (cachedResponse) {
      return cachedResponse;
    }
    
    // Se não há cache, retorna erro offline
    return new Response(JSON.stringify({ 
      error: 'Sem conexão com a internet',
      offline: true 
    }), {
      status: 503,
      statusText: 'Service Unavailable',
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// Estratégia Network First com fallback para offline
async function networkFirstWithFallback(request) {
  try {
    const networkResponse = await fetch(request);
    
    // Cacheia páginas HTML para acesso offline
    if (networkResponse.status === 200) {
      const cache = await caches.open(DYNAMIC_CACHE_NAME);
      cache.put(request, networkResponse.clone());
    }
    
    return networkResponse;
  } catch (error) {
    // Tenta cache primeiro
    const cache = await caches.open(DYNAMIC_CACHE_NAME);
    const cachedResponse = await cache.match(request);
    
    if (cachedResponse) {
      return cachedResponse;
    }
    
    // Fallback para página offline
    return caches.match('/').then(response => {
      return response || new Response(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>IntelliMen - Offline</title>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <style>
            body { 
              font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
              display: flex; 
              justify-content: center; 
              align-items: center; 
              min-height: 100vh; 
              margin: 0; 
              background: linear-gradient(135deg, #000 0%, #333 100%);
              color: white;
              text-align: center;
              padding: 20px;
            }
            .offline-container {
              max-width: 400px;
              padding: 40px;
              background: rgba(255,255,255,0.1);
              border-radius: 20px;
              backdrop-filter: blur(10px);
            }
            .logo { font-size: 3rem; margin-bottom: 20px; }
            h1 { margin-bottom: 20px; font-size: 1.5rem; }
            p { opacity: 0.8; line-height: 1.6; margin-bottom: 30px; }
            button {
              background: white;
              color: #000;
              border: none;
              padding: 15px 30px;
              border-radius: 10px;
              font-weight: 600;
              cursor: pointer;
              font-size: 1rem;
            }
          </style>
        </head>
        <body>
          <div class="offline-container">
            <div class="logo">🎯</div>
            <h1>IntelliMen Offline</h1>
            <p>Você está sem conexão com a internet. Alguns recursos podem não estar disponíveis.</p>
            <button onclick="window.location.reload()">🔄 Tentar Novamente</button>
          </div>
        </body>
        </html>
      `, {
        headers: { 'Content-Type': 'text/html' }
      });
    });
  }
}

// Estratégia Stale While Revalidate (retorna cache imediatamente, atualiza em background)
async function staleWhileRevalidateStrategy(request) {
  const cache = await caches.open(DYNAMIC_CACHE_NAME);
  const cachedResponse = await cache.match(request);
  
  // Busca atualizada em background
  const fetchPromise = fetch(request).then(response => {
    if (response.status === 200) {
      cache.put(request, response.clone());
    }
    return response;
  }).catch(() => null);
  
  // Retorna cache imediatamente se disponível, senão espera a rede
  return cachedResponse || fetchPromise;
}

// Mensagens do cliente
self.addEventListener('message', event => {
  console.log('📨 Service Worker: Mensagem recebida:', event.data);
  
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
  
  if (event.data && event.data.type === 'GET_VERSION') {
    event.ports[0].postMessage({
      version: CACHE_NAME
    });
  }
  
  if (event.data && event.data.type === 'CLEAR_CACHE') {
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames
          .filter(cacheName => cacheName.startsWith('intellimen-'))
          .map(cacheName => caches.delete(cacheName))
      );
    }).then(() => {
      event.ports[0].postMessage({ success: true });
    });
  }
});

// Background Sync (para ações offline)
self.addEventListener('sync', event => {
  console.log('🔄 Service Worker: Background Sync:', event.tag);
  
  if (event.tag === 'background-sync-challenge') {
    event.waitUntil(syncChallengeProgress());
  }
});

// Sincronizar progresso dos desafios quando voltar online
async function syncChallengeProgress() {
  try {
    // Recuperar dados pendentes do IndexedDB
    const pendingData = await getOfflineData();
    
    if (pendingData.length > 0) {
      console.log('📤 Sincronizando dados offline...');
      
      for (const data of pendingData) {
        try {
          await fetch(data.url, {
            method: data.method,
            headers: data.headers,
            body: data.body
          });
          
          // Remove da fila offline após sucesso
          await removeOfflineData(data.id);
        } catch (error) {
          console.error('❌ Erro ao sincronizar:', error);
        }
      }
      
      console.log('✅ Sincronização concluída');
      
      // Notificar clientes sobre sincronização
      const clients = await self.clients.matchAll();
      clients.forEach(client => {
        client.postMessage({
          type: 'SYNC_COMPLETE',
          synced: pendingData.length
        });
      });
    }
  } catch (error) {
    console.error('❌ Erro na sincronização:', error);
  }
}

// Funções auxiliares para IndexedDB (simuladas)
async function getOfflineData() {
  // Implementação real usaria IndexedDB
  return [];
}

async function removeOfflineData(id) {
  // Implementação real usaria IndexedDB
  return true;
}

// Notificações Push (para futuras atualizações)
self.addEventListener('push', event => {
  console.log('🔔 Service Worker: Push recebido:', event);
  
  if (event.data) {
    const data = event.data.json();
    
    const options = {
      body: data.body || 'Nova atualização disponível!',
      icon: '/icon-192x192.png',
      badge: '/icon-72x72.png',
      vibrate: [100, 50, 100],
      data: data.url || '/',
      actions: [
        {
          action: 'view',
          title: 'Ver',
          icon: '/icon-72x72.png'
        },
        {
          action: 'close',
          title: 'Fechar'
        }
      ]
    };
    
    event.waitUntil(
      self.registration.showNotification(data.title || 'IntelliMen', options)
    );
  }
});

// Clique em notificações
self.addEventListener('notificationclick', event => {
  console.log('🔔 Service Worker: Notificação clicada:', event);
  
  event.notification.close();
  
  if (event.action === 'view') {
    event.waitUntil(
      self.clients.openWindow(event.notification.data || '/')
    );
  }
});

console.log('✅ Service Worker IntelliMen carregado');