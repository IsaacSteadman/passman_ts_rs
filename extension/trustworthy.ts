// Which hosts a plain-HTTP server may be on: the ones browsers count as
// "potentially trustworthy" (so pages there get secure-context features such
// as `crypto.subtle`), i.e. this computer. Anywhere else, HTTP would send the
// account's auth key and the server password across the network in the clear.

export function isPotentiallyTrustworthy(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  // IPv6 loopback (URL hostnames keep the brackets)
  if (host === "[::1]") return true;
  // 127.0.0.0/8
  const parts = host.split(".");
  return (
    parts.length === 4 &&
    parts[0] === "127" &&
    parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255)
  );
}
