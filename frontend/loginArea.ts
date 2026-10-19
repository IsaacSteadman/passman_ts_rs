import { decryptBlob, deriveKey, SALT_LEN } from "./passman_crypto_glue";
import { type VaultRoot } from "./PassTable";

export interface LoginResult {
  data: VaultRoot;
  lastModified: string | null;
  /** Full 64-byte Argon2 output — XChaCha20 uses only the first 32 bytes. */
  encryptionKey: Uint8Array;
  username: string;
  authKeyB64: string;
  serverPass: string;
  serverNs: string | null;
}

function getAlg() {
  const alg = {
    32: "SHA-256" as const,
    48: "SHA-384" as const,
    64: "SHA-512" as const,
  }[SALT_LEN];
  if (alg == null) throw new Error(`Unsupported SALT_LEN: ${SALT_LEN}`);
  return alg;
}

/** Derives the auth and encryption keys for a given username + password. */
export async function deriveUserKeys(
  username: string,
  password: string,
): Promise<{ authKeyB64: string; encryptionKey: Uint8Array }> {
  const alg = getAlg();
  const escapedUsername = JSON.stringify(username);
  const enc = new TextEncoder();

  const saltAuth = new Uint8Array(
    await crypto.subtle.digest(alg, enc.encode(`auth:${escapedUsername}`)),
  );
  const saltEncryption = new Uint8Array(
    await crypto.subtle.digest(
      alg,
      enc.encode(`encryption:${escapedUsername}`),
    ),
  );

  const authKey = deriveKey(password, saltAuth);
  const encryptionKey = deriveKey(password, saltEncryption);

  const authKeyB64 = btoa(String.fromCharCode(...authKey))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  return { authKeyB64, encryptionKey };
}

/** Credentials go in headers rather than the URL so they stay out of server
 *  and proxy logs. The server password is percent-encoded because header
 *  values must be ASCII. */
export function credentialHeaders(
  authKeyB64: string,
  serverPass: string,
): Record<string, string> {
  return {
    "Passman-Auth-Key": authKeyB64,
    "Passman-Server-Pass": encodeURIComponent(serverPass),
  };
}

/** Reads server_pass and server_ns from the #server-access form. */
export function readServerAccessParams(): {
  serverPass: string;
  serverNs: string | null;
} {
  const form = document.querySelector(
    "form#server-access",
  ) as HTMLFormElement | null;
  const serverPass =
    (
      form?.querySelector(
        "input[name='server_pass']",
      ) as HTMLInputElement | null
    )?.value ?? "";
  const serverNsRaw =
    (form?.querySelector("input[name='server_ns']") as HTMLInputElement | null)
      ?.value ?? "";
  return { serverPass, serverNs: serverNsRaw || null };
}

export function initLoginArea(
  errorPanel: HTMLElement,
  onLogin: (result: LoginResult) => void,
): void {
  const loginDiv = document.querySelector("div#login") as HTMLDivElement;
  const form = loginDiv.querySelector("form")!;
  const usernameInput = form.querySelector(
    "input[name='username']",
  ) as HTMLInputElement;
  const passwordInput = form.querySelector(
    "input[name='password']",
  ) as HTMLInputElement;
  const showPasswordCheckbox = form.querySelector(
    "input[name='show-password']",
  ) as HTMLInputElement;
  showPasswordCheckbox.addEventListener("change", () => {
    passwordInput.type = showPasswordCheckbox.checked ? "text" : "password";
  });
  const submitButton = form.querySelector(
    "input[name='submit']",
  ) as HTMLInputElement;

  submitButton.addEventListener("click", async (event) => {
    event.preventDefault();
    errorPanel.textContent = "";
    const username = usernameInput.value;
    const password = passwordInput.value;
    const { serverPass, serverNs } = readServerAccessParams();

    let authKeyB64: string;
    let encryptionKey: Uint8Array;
    try {
      ({ authKeyB64, encryptionKey } = await deriveUserKeys(
        username,
        password,
      ));
    } catch (e) {
      errorPanel.textContent = `Key derivation failed: ${e}`;
      return;
    }

    const url = new URL("/pass-table", window.location.origin);
    url.searchParams.set("username", username);
    if (serverNs != null) url.searchParams.set("server_ns", serverNs);

    let response: Response;
    try {
      response = await fetch(url.toString(), {
        headers: credentialHeaders(authKeyB64, serverPass),
      });
    } catch (e) {
      errorPanel.textContent = `Network error: ${e}`;
      return;
    }

    if (!response.ok) {
      let body: unknown;
      try {
        body = await response.json();
      } catch {
        body = await response.text();
      }
      errorPanel.textContent = `Login failed (${response.status}): ${JSON.stringify(body)}`;
      return;
    }

    const lastModified = response.headers.get("Last-Modified");
    const blob = new Uint8Array(await response.arrayBuffer());

    let data: VaultRoot;
    try {
      const plaintext = decryptBlob(encryptionKey, blob);
      const parsed: unknown = JSON.parse(new TextDecoder().decode(plaintext));
      if (Array.isArray(parsed)) {
        // Migration: old format (PassTableData[] without ids)
        data = {
          tables: (parsed as any[]).map((table: any) => {
            const numRows = table.columns?.[0]?.data?.length ?? 0;
            return {
              id: crypto.randomUUID(),
              rowIds: Array.from({ length: numRows }, () =>
                crypto.randomUUID(),
              ),
              name: table.name ?? "Table",
              columns: (table.columns ?? []).map((col: any) => ({
                id: crypto.randomUUID(),
                label: col.label ?? "Column",
                type: col.type ?? "textarea",
                data: col.data ?? [],
              })),
            };
          }),
          history: [],
        };
      } else {
        data = parsed as VaultRoot;
      }
    } catch (e) {
      errorPanel.textContent = `Decryption or parse failed: ${e}`;
      return;
    }

    passwordInput.value = "";
    onLogin({
      data,
      lastModified,
      encryptionKey,
      username,
      authKeyB64,
      serverPass,
      serverNs,
    });
  });
}
