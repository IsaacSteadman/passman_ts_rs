// The web app inside the Android app (android/). The app ships these pages in
// its APK rather than loading them from the server, and its web view may not
// reach the network: what the pages can't do themselves, they ask the app for
// through `passmanNative`, which it gives only to its own pages. The app:
//
//  - sends requests to the server (only that server, optionally only with the
//    certificate key it had when it was set up),
//  - keeps biometric unlock's keys in the Android Keystore (in secure hardware
//    where the device has it), usable only after a biometric check,
//  - marks copied text sensitive and clears it from the clipboard again,
//  - saves exports with the system's file picker.

import {
  decodeSecrets,
  encodeSecrets,
  setKeyProtector,
  UnlockError,
  type KeyProtector,
} from "./keyProtector";
import { deleteUnlockKey, getUnlockKey, putUnlockKey } from "./deviceStore";
import { fromBase64Url, toBase64Url } from "./passman_crypto_glue";
import { setClipboardWriter } from "./PassTable";
import { setFileSaver } from "./importExportPanel";
import { setServerOrigin, setServerTransport } from "./serverOrigin";

/** The object the app injects (an androidx.webkit web message listener). */
interface NativeBridge {
  postMessage(message: string): void;
  addEventListener(
    type: "message",
    listener: (event: MessageEvent<string>) => void,
  ): void;
}

declare global {
  var passmanNative: NativeBridge | undefined;
}

/** The bridge when running inside the Android app, else null. */
export function nativeBridge(): NativeBridge | null {
  return globalThis.passmanNative ?? null;
}

/** A failed call; `kind` says why ("cancelled", "invalidated", "offline",
 *  "key-changed" or "error"). */
export class NativeError extends Error {
  constructor(
    message: string,
    readonly kind: string,
  ) {
    super(message);
  }
}

type Reply =
  | { id: number; result: unknown }
  | { id: number; error: { message: string; kind: string } };

let nextId = 1;
const pending = new Map<
  number,
  { resolve: (value: unknown) => void; reject: (error: NativeError) => void }
>();
let listening = false;

/** Calls `method` in the app. */
export function callNative<T>(
  method: string,
  params: Record<string, unknown> = {},
): Promise<T> {
  const bridge = nativeBridge();
  if (bridge == null)
    return Promise.reject(new NativeError("not in the app", "error"));
  if (!listening) {
    listening = true;
    bridge.addEventListener("message", (event) => {
      const reply = JSON.parse(event.data) as Reply;
      const call = pending.get(reply.id);
      if (call == null) return;
      pending.delete(reply.id);
      if ("error" in reply)
        call.reject(new NativeError(reply.error.message, reply.error.kind));
      else call.resolve(reply.result);
    });
  }
  const id = nextId++;
  return new Promise<T>((resolve, reject) => {
    pending.set(id, {
      resolve: (value) => resolve(value as T),
      reject,
    });
    bridge.postMessage(JSON.stringify({ id, method, params }));
  });
}

// ── Requests to the server ──────────────────────────────────────────────────

interface NativeResponse {
  status: number;
  statusText: string;
  headers: [string, string][];
  body: string;
}

/** Statuses whose responses may not have a body. */
const NULL_BODY = [101, 204, 205, 304];

async function nativeFetch(url: string, init: RequestInit): Promise<Response> {
  // Request does the work of reading any kind of body and headers (and drops
  // those a page may not set, such as Content-Length)
  const request = new Request(url, init);
  const body =
    init.body == null ? null : new Uint8Array(await request.arrayBuffer());
  let response: NativeResponse;
  try {
    response = await callNative<NativeResponse>("fetch", {
      url: request.url,
      method: request.method,
      headers: [...request.headers],
      body: body && toBase64Url(body),
    });
  } catch (e) {
    // like fetch: rejected when no response arrived
    throw new TypeError(e instanceof Error ? e.message : String(e));
  }
  return new Response(
    NULL_BODY.includes(response.status) ? null : fromBase64Url(response.body),
    {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    },
  );
}

// ── Biometric unlock with the Android Keystore ──────────────────────────────

interface KeystoreUnlockKey {
  id: string;
  /** The Keystore key's alias; random, so it doesn't name the account. */
  alias: string;
  /** The account's keys, encrypted by the Keystore key with the account id
   *  as additional data; null when out of date. */
  wrapped: { iv: string; ciphertext: string } | null;
}

const records = new Map<string, KeystoreUnlockKey | null>();

async function load(accountId: string): Promise<KeystoreUnlockKey | null> {
  if (!records.has(accountId))
    records.set(
      accountId,
      (await getUnlockKey<KeystoreUnlockKey>(accountId)) ?? null,
    );
  return records.get(accountId)!;
}

async function store(record: KeystoreUnlockKey): Promise<void> {
  await putUnlockKey(record);
  records.set(record.id, record);
}

async function forget(accountId: string, alias: string): Promise<void> {
  await deleteUnlockKey(accountId);
  records.set(accountId, null);
  await callNative("removeKey", { alias });
}

/** A KeyProtector error as one the UI shows as is. */
async function biometricError(
  e: unknown,
  record: KeystoreUnlockKey,
): Promise<UnlockError> {
  if (!(e instanceof NativeError)) return new UnlockError(String(e));
  if (e.kind === "cancelled")
    return new UnlockError("Biometric check cancelled.");
  if (e.kind === "invalidated") {
    // the Keystore deleted the key when biometrics were added or removed
    await forget(record.id, record.alias);
    return new UnlockError(
      "This device's biometrics changed, so biometric unlock was turned off. Unlock with the password, then turn it on again.",
    );
  }
  return new UnlockError(`Biometric unlock failed: ${e.message}`);
}

const keystoreProtector: KeyProtector = {
  async isSupported() {
    try {
      return await callNative<boolean>("biometricsAvailable");
    } catch {
      return false;
    }
  },

  async status(accountId) {
    const record = await load(accountId);
    // the key never leaves this device
    return record && { current: record.wrapped != null, synced: false };
  },

  async protect(accountId, _label, secrets) {
    const record = (await load(accountId)) ?? {
      id: accountId,
      alias: crypto.randomUUID(),
      wrapped: null,
    };
    let wrapped: KeystoreUnlockKey["wrapped"];
    try {
      wrapped = await callNative<NonNullable<KeystoreUnlockKey["wrapped"]>>(
        "protect",
        {
          alias: record.alias,
          aad: accountId,
          secret: toBase64Url(encodeSecrets(secrets)),
        },
      );
    } catch (e) {
      throw await biometricError(e, record);
    }
    await store({ ...record, wrapped });
  },

  async unlock(accountId) {
    const record = await load(accountId);
    if (record?.wrapped == null)
      throw new UnlockError(
        "Biometric unlock isn't set up for this account; unlock with the password.",
      );
    let secret: string;
    try {
      ({ secret } = await callNative<{ secret: string }>("unprotect", {
        alias: record.alias,
        aad: accountId,
        ...record.wrapped,
      }));
    } catch (e) {
      throw await biometricError(e, record);
    }
    return decodeSecrets(fromBase64Url(secret).buffer);
  },

  async invalidate(accountId) {
    const record = await load(accountId);
    if (record?.wrapped != null) await store({ ...record, wrapped: null });
  },

  async remove(accountId) {
    const record = await load(accountId);
    if (record) await forget(accountId, record.alias);
  },
};

// ── Starting ────────────────────────────────────────────────────────────────

export interface NativeConfig {
  /** The server's origin. */
  server: string;
  /** Set when the app only accepts the server's certificate key it had when
   *  it was set up: that key's SHA-256 fingerprint. */
  pinnedKey: string | null;
}

/** Hooks the app into the rest of the web app. */
export async function startNativeApp(): Promise<NativeConfig> {
  const config = await callNative<NativeConfig>("config");
  setServerOrigin(config.server);
  setServerTransport(nativeFetch);
  setKeyProtector(keystoreProtector);
  setClipboardWriter((text) => void callNative("copy", { text }));
  setFileSaver(
    (name, text, type) => void callNative("saveFile", { name, text, type }),
  );
  return config;
}
