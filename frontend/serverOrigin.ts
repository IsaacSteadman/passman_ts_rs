// Where the Passman server is. The web app is served by it, so it's the page's
// own origin; the browser extensions talk to a server the user picks.

let configured: string | null = null;

/** Sets the server's origin (e.g. "https://passman.example.com"). */
export function setServerOrigin(origin: string): void {
  configured = origin;
}

/** The URL of `path` on the server. */
export function serverUrl(path: string): URL {
  return new URL(path, configured ?? window.location.origin);
}
