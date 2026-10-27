// Where the Passman server is, and how to reach it. The web app is served by
// it, so it's the page's own origin; the browser extensions and the Android app
// talk to a server the user picks. The Android app also sends the requests
// itself (see nativeApp.ts), as its pages may not reach the network.

let configured: string | null = null;

/** Sets the server's origin (e.g. "https://passman.example.com"). */
export function setServerOrigin(origin: string): void {
  configured = origin;
}

/** The URL of `path` on the server. */
export function serverUrl(path: string): URL {
  return new URL(path, configured ?? window.location.origin);
}

export type ServerTransport = (
  url: string,
  init: RequestInit,
) => Promise<Response>;

let transport: ServerTransport = (url, init) => fetch(url, init);

/** Replaces how requests to the server are sent. */
export function setServerTransport(replacement: ServerTransport): void {
  transport = replacement;
}

/** Sends a request to the server; like `fetch`, rejects only when no response
 *  arrived. */
export function serverFetch(
  url: URL,
  init: RequestInit = {},
): Promise<Response> {
  return transport(url.toString(), init);
}
