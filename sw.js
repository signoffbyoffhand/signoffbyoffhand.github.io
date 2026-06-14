/* SignOff service worker — pełny offline + bezpieczna automatyczna aktualizacja.
   Nowa wersja pobiera się w tle (gdy online), ale aktywuje się dopiero gdy użytkownik
   dotknie „Odśwież" albo przy następnym otwarciu aplikacji — nigdy w trakcie zgody. */
const CACHE = "signoff-v10";
const ASSETS = [
  "./", "index.html", "style.css", "app.js", "manifest.json",
  "icons/icon-192.png", "icons/icon-512.png", "icons/offhand-logo.svg",
  "vendor/pdf-lib.min.js", "vendor/fontkit.umd.min.js",
  "vendor/DejaVuSans.ttf", "vendor/DejaVuSans-Bold.ttf",
];
self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)));
});
self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener("message", (e) => {
  if (e.data && e.data.type === "SKIP_WAITING") self.skipWaiting();
});
/* network-first: świeża wersja gdy online, pełny offline z cache gdy brak sieci.
   API synchronizacji i żądania inne niż GET idą zawsze prosto do sieci. */
self.addEventListener("fetch", (e) => {
  const u = new URL(e.request.url);
  if (e.request.method !== "GET" || u.origin !== location.origin || u.pathname.startsWith("/api/")) return;
  e.respondWith(
    fetch(e.request).then(resp => {
      if (resp.ok && e.request.method === "GET" && new URL(e.request.url).origin === location.origin) {
        const copy = resp.clone();
        caches.open(CACHE).then(c => c.put(e.request, copy));
      }
      return resp;
    }).catch(() => caches.match(e.request, { ignoreSearch: true }))
  );
});
