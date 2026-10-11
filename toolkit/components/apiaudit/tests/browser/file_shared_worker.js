// APIAUDIT_SHARED_MARKER
self.onconnect = event => {
  navigator.hardwareConcurrency;
  event.ports[0].postMessage("ready");
};
