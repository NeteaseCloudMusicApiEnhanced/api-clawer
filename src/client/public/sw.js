// 无缓存透传 Service Worker
// 仅用于 PWA 安装能力，不缓存任何资源

self.addEventListener('install', function() {
  // 立即激活，不等待页面关闭
  self.skipWaiting();
});

self.addEventListener('activate', function() {
  // 接管所有客户端
  self.clients.claim();
});

self.addEventListener('fetch', function(event) {
  // 纯透传：不缓存任何内容，每次都请求网络
  // 如果网络不可用，请求失败由浏览器自行处理
  event.respondWith(fetch(event.request));
});
