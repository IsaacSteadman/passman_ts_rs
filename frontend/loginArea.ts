import {
  accountId,
  getAccount,
  getVault,
  type CachedVault,
} from "./deviceStore";
import { decryptBlob, deriveKey, SALT_LEN } from "./passman_crypto_glue";
import {
  type CellValue,
  type PassTableColumn,
  type VaultRoot,
} from "./PassTable";

/** A version of the vault as stored on the server. */
export interface SyncedVault {
  data: VaultRoot;
  /** The encrypted vault exactly as the server holds it. */
  blob: Uint8Array;
  /** The version, sent back as If-Match when saving. */
  etag: string | null;
  lastModified: string | null;
}

export interface LoginResult {
  username: string;
  serverPass: string;
  serverNs: string | null;
  authKeyB64: string;
  /** Full 64-byte Argon2 output — XChaCha20 uses only the first 32 bytes. */
  encryptionKey: Uint8Array;
  /** The server version this session starts from. */
  synced: SyncedVault;
  /** Changes made on this device that the server doesn't have yet. */
  pending: VaultRoot | null;
  /** Whether the account is (or is to be) remembered on this device. */
  remember: boolean;
  /** Whether `synced` was read from this device's cache rather than
   *  downloaded just now, so a newer version may be on the server. */
  fromCache: boolean;
  /** Set when the password was changed in another session: this device's
   *  copy (and biometric unlock) still use the old keys. */
  keysChanged: boolean;
}

/** Vaults saved before tables had ids were a bare array of these. */
type LegacyTable = {
  name?: string;
  columns?: {
    label?: string;
    type?: PassTableColumn["type"];
    data?: CellValue[];
  }[];
};

/** Decrypts and parses a vault downloaded from the server (throws on failure). */
export function decodeVault(
  encryptionKey: Uint8Array,
  blob: Uint8Array,
): VaultRoot {
  const plaintext = decryptBlob(encryptionKey, blob);
  const parsed: unknown = JSON.parse(new TextDecoder().decode(plaintext));
  if (!Array.isArray(parsed)) return parsed as VaultRoot;
  // Migration: old format (PassTableData[] without ids)
  return {
    tables: (parsed as LegacyTable[]).map((table) => {
      const numRows = table.columns?.[0]?.data?.length ?? 0;
      return {
        id: crypto.randomUUID(),
        rowIds: Array.from({ length: numRows }, () => crypto.randomUUID()),
        name: table.name ?? "Table",
        columns: (table.columns ?? []).map(
          (col) =>
            ({
              id: crypto.randomUUID(),
              label: col.label ?? "Column",
              type: col.type ?? "textarea",
              data: col.data ?? [],
            }) as PassTableColumn,
        ),
      };
    }),
    history: [],
  };
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

/** The text of an error response, and its "type" field if it is JSON. */
export async function describeError(
  response: Response,
): Promise<{ message: string; type: string | null }> {
  const text = await response.text();
  let type: string | null = null;
  try {
    const body: unknown = JSON.parse(text);
    if (body != null && typeof body === "object" && "type" in body)
      type = String(body.type);
  } catch {
    // not JSON
  }
  return { message: `(${response.status}): ${text}`, type };
}

export type Download =
  | {
      ok: true;
      blob: Uint8Array;
      etag: string | null;
      lastModified: string | null;
    }
  | {
      ok: false;
      /** "offline": the server couldn't be reached; "credentials": the server
       *  rejected the auth key (wrong password, or changed in another
       *  session). */
      reason: "offline" | "credentials" | "error";
      message: string;
    };

/** Downloads the encrypted vault. */
export async function downloadVault(
  username: string,
  serverNs: string | null,
  serverPass: string,
  authKeyB64: string,
): Promise<Download> {
  const url = new URL("/pass-table", window.location.origin);
  url.searchParams.set("username", username);
  if (serverNs != null) url.searchParams.set("server_ns", serverNs);
  try {
    const response = await fetch(url.toString(), {
      headers: credentialHeaders(authKeyB64, serverPass),
      cache: "no-store",
    });
    if (!response.ok) {
      const { message, type } = await describeError(response);
      return {
        ok: false,
        reason: type === "E_AUTH" ? "credentials" : "error",
        message,
      };
    }
    return {
      ok: true,
      blob: new Uint8Array(await response.arrayBuffer()),
      etag: response.headers.get("ETag"),
      lastModified: response.headers.get("Last-Modified"),
    };
  } catch (e) {
    // fetch rejects only when no response arrived
    return { ok: false, reason: "offline", message: `Network error: ${e}` };
  }
}

/** Decrypts a vault cached on this device (throws if the key is wrong). */
function decodeCached(
  encryptionKey: Uint8Array,
  cached: CachedVault,
): { synced: SyncedVault; pending: VaultRoot | null } {
  return {
    synced: {
      data: decodeVault(encryptionKey, cached.syncedBlob),
      blob: cached.syncedBlob,
      etag: cached.syncedEtag,
      lastModified: cached.syncedLastModified,
    },
    pending:
      cached.pendingBlob && decodeVault(encryptionKey, cached.pendingBlob),
  };
}

export interface UserKeys {
  authKeyB64: string;
  encryptionKey: Uint8Array;
}

/** Checks a password and loads the vault (see `unlockWithKeys`). Returns an
 *  error message on failure. */
export async function unlockWithPassword(
  username: string,
  serverNs: string | null,
  serverPass: string,
  password: string,
  remember: boolean,
): Promise<LoginResult | string> {
  let keys: UserKeys;
  try {
    keys = await deriveUserKeys(username, password);
  } catch (e) {
    return `Key derivation failed: ${e}`;
  }
  return unlockWithKeys(username, serverNs, serverPass, keys, remember);
}

/**
 * Loads the vault with keys from the password or from biometric unlock. An
 * account remembered on this device is unlocked from its cached copy, which
 * works offline: wrong keys fail to decrypt it. Other accounts are downloaded
 * from the server. Returns an error message on failure.
 */
export async function unlockWithKeys(
  username: string,
  serverNs: string | null,
  serverPass: string,
  keys: UserKeys,
  remember: boolean,
): Promise<LoginResult | string> {
  const { authKeyB64, encryptionKey } = keys;
  const id = accountId(username, serverNs);
  const account = await getAccount(id);
  const cached = account && (await getVault(id));
  // the server password isn't asked for again when unlocking a remembered
  // account
  serverPass ||= account?.serverPass ?? "";
  const result = { username, serverNs, serverPass, authKeyB64, encryptionKey };

  if (cached) {
    try {
      return {
        ...result,
        ...decodeCached(encryptionKey, cached),
        remember: true,
        fromCache: true,
        keysChanged: false,
      };
    } catch {
      // a wrong password, or the password was changed in another session:
      // only the server can tell which
    }
  }

  const download = await downloadVault(
    username,
    serverNs,
    serverPass,
    authKeyB64,
  );
  if (!download.ok) {
    if (cached && download.reason === "offline")
      return "Wrong password. (If it was changed on another device, connect to the internet to unlock with the new one.)";
    if (download.reason === "credentials") return "Wrong username or password.";
    return `Login failed ${download.message}`;
  }
  if (cached?.pendingBlob)
    // the password was changed in another session, and this device's unsaved
    // changes are encrypted with the old one
    return "The password was changed in another session, but this device has changes that weren't saved yet. Unlock with the previous password to keep them (you'll then be asked for the new one), or forget this account on this device to discard them.";

  let data: VaultRoot;
  try {
    data = decodeVault(encryptionKey, download.blob);
  } catch (e) {
    return `Decryption or parse failed: ${e}`;
  }
  return {
    ...result,
    synced: {
      data,
      blob: download.blob,
      etag: download.etag,
      lastModified: download.lastModified,
    },
    pending: null,
    remember: remember || account != null,
    fromCache: false,
    keysChanged: cached != null,
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

  const rememberCheckbox = form.querySelector(
    "input[name='remember']",
  ) as HTMLInputElement;

  submitButton.addEventListener("click", async (event) => {
    event.preventDefault();
    errorPanel.textContent = "";
    const { serverPass, serverNs } = readServerAccessParams();
    submitButton.disabled = true;
    try {
      const result = await unlockWithPassword(
        usernameInput.value,
        serverNs,
        serverPass,
        passwordInput.value,
        rememberCheckbox.checked,
      );
      if (typeof result === "string") {
        errorPanel.textContent = result;
        return;
      }
      passwordInput.value = "";
      rememberCheckbox.checked = false;
      onLogin(result);
    } finally {
      submitButton.disabled = false;
    }
  });
}
