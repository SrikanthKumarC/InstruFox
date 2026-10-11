// APIAUDIT_SW_MARKER
self.addEventListener("install", () => {
  navigator.hardwareConcurrency;
  self.skipWaiting();
});
self.addEventListener("activate", event => {
  event.waitUntil(self.clients.claim());
});
