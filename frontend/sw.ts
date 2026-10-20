// Service worker: keeps a copy of the app so it starts offline. The vault is
// never handled here; API requests go straight to the network, and the vault
// cached for offline use is kept (encrypted) in IndexedDB by the page.
//
// Type-checked with tsconfig.sw.json (it needs the WebWorker types).

import { manifest, version } from "@parcel/service-worker";

declare const self: ServiceWorkerGlobalScope;

const CACHE = `passman-${version}`;
/** The page itself, cached under this URL whatever query it was loaded with. */
const PAGE = "/";
/** How long a page load waits for the network before using the cached copy. */
const NETWORK_TIMEOUT_MS = 4000;

self.addEventListener("install", (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(CACHE);
      await cache.addAll([PAGE, ...manifest]);
      // replace the previous version right away; the page loads everything it
      // needs at startup, so a running page isn't affected
      await self.skipWaiting();
    })(),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      for (const key of await caches.keys())
        if (key !== CACHE) await caches.delete(key);
      await self.clients.claim();
    })(),
  );
});

/** The network's response, or undefined if it failed or took too long. */
async function fromNetwork(request: Request): Promise<Response | undefined> {
  const timeout = new Promise<undefined>((resolve) =>
    setTimeout(resolve, NETWORK_TIMEOUT_MS),
  );
  const network = fetch(request).catch(() => undefined);
  return Promise.race([network, timeout]);
}

self.addEventListener("fetch", (event) => {
  const { request } = event;
  const url = new URL(request.url);
  if (request.method !== "GET" || url.origin !== self.location.origin) return;

  if (request.mode === "navigate") {
    // the page: the latest from the network, so updates apply on the next
    // load; the cached copy when offline
    event.respondWith(
      (async () => {
        const response = await fromNetwork(request);
        if (response?.ok) {
          const copy = response.clone();
          event.waitUntil(
            caches.open(CACHE).then((cache) => cache.put(PAGE, copy)),
          );
          return response;
        }
        return response ?? (await caches.match(PAGE)) ?? Response.error();
      })(),
    );
    return;
  }

  // the app's other files were cached together with this service worker, so
  // they match this version of the app (a new build installs a new one)
  if (manifest.includes(url.pathname))
    event.respondWith(
      (async () => (await caches.match(request)) ?? fetch(request))(),
    );
});
