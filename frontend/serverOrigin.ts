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

/** The error type of a JSON error response, if any. */
async function errorType(response: Response): Promise<string | null> {
  try {
    const body: unknown = await response.clone().json();
    if (body != null && typeof body === "object" && "type" in body)
      return String(body.type);
  } catch {
    // not JSON
  }
  return null;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** The longest wait a request is retried after by itself (longer ones, like
 *  a ban, are reported to the user). */
const MAX_AUTO_WAIT_S = 15;

/** Sends a request to the server; like `fetch`, rejects only when no response
 *  arrived. Retries by itself when the server asks to:
 *  - 409 `E_AUTH_CONFLICT`: another request for the account was upgrading
 *    its lock at the same moment; retried after a short random wait;
 *  - 429 with a short `Retry-After`: too many requests, or the account had
 *    many failed logins and this device must wait before trying it. */
export async function serverFetch(
  url: URL,
  init: RequestInit = {},
): Promise<Response> {
  for (let attempt = 0; ; attempt++) {
    const response = await transport(url.toString(), init);
    if (attempt >= 5) return response;
    if (response.status === 409) {
      if ((await errorType(response)) !== "E_AUTH_CONFLICT") return response;
      await sleep((50 + Math.random() * 200) * 2 ** attempt);
      continue;
    }
    if (response.status === 429) {
      const type = await errorType(response);
      const wait = Number(response.headers.get("Retry-After"));
      if (
        type === "E_BANNED" ||
        !Number.isFinite(wait) ||
        wait > MAX_AUTO_WAIT_S
      )
        return response;
      await sleep(Math.max(wait, 1) * 1000 + Math.random() * 250);
      continue;
    }
    return response;
  }
}
