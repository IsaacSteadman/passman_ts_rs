// Accounts remembered on this device, kept in IndexedDB. Nothing here is
// synced to the server or between devices. The vault blobs are encrypted with
// the account's encryption key, exactly like the copy on the server; the
// account record itself (username, namespace, server password) is not
// encrypted, so the lock screen can list it before anything is unlocked.

export interface RememberedAccount {
  id: string;
  username: string;
  serverNs: string | null;
  serverPass: string;
  /** When this account was last unlocked on this device (ms since epoch). */
  lastUsed: number;
}

export interface CachedVault {
  id: string;
  /** The vault as last downloaded from or saved to the server. It is the
   *  base for merging this device's unsaved changes. */
  syncedBlob: Uint8Array;
  syncedEtag: string | null;
  syncedLastModified: string | null;
  /** This device's changes the server doesn't have yet, if any. */
  pendingBlob: Uint8Array | null;
}

const DB_NAME = "passman";
const DB_VERSION = 1;
const ACCOUNTS = "accounts";
const VAULTS = "vaults";

/** Every store holding per-account data, so forgetting an account clears all
 *  of it. */
const ACCOUNT_STORES = [ACCOUNTS, VAULTS];

export function accountId(username: string, serverNs: string | null): string {
  return JSON.stringify([serverNs ?? "", username]);
}

let dbPromise: Promise<IDBDatabase> | null = null;

function openDb(): Promise<IDBDatabase> {
  dbPromise ??= new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      for (const name of ACCOUNT_STORES)
        if (!db.objectStoreNames.contains(name))
          db.createObjectStore(name, { keyPath: "id" });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => {
      dbPromise = null;
      reject(request.error);
    };
  });
  return dbPromise;
}

/** Runs `body` in one transaction and resolves once it has committed. The
 *  transaction is created as soon as the database is open, so transactions
 *  started in some order also run in that order. */
async function transaction<T>(
  stores: string[],
  mode: IDBTransactionMode,
  body: (tx: IDBTransaction) => IDBRequest<T> | void,
): Promise<T | undefined> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(stores, mode);
    const request = body(tx);
    tx.oncomplete = () => resolve(request ? request.result : undefined);
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error);
  });
}

export async function listAccounts(): Promise<RememberedAccount[]> {
  const accounts = await transaction<RememberedAccount[]>(
    [ACCOUNTS],
    "readonly",
    (tx) => tx.objectStore(ACCOUNTS).getAll(),
  );
  return (accounts ?? []).sort((a, b) => b.lastUsed - a.lastUsed);
}

export async function getAccount(
  id: string,
): Promise<RememberedAccount | undefined> {
  return transaction<RememberedAccount>([ACCOUNTS], "readonly", (tx) =>
    tx.objectStore(ACCOUNTS).get(id),
  );
}

export async function putAccount(account: RememberedAccount): Promise<void> {
  await transaction([ACCOUNTS], "readwrite", (tx) => {
    tx.objectStore(ACCOUNTS).put(account);
  });
}

export async function getVault(id: string): Promise<CachedVault | undefined> {
  return transaction<CachedVault>([VAULTS], "readonly", (tx) =>
    tx.objectStore(VAULTS).get(id),
  );
}

export async function putVault(vault: CachedVault): Promise<void> {
  await transaction([VAULTS], "readwrite", (tx) => {
    tx.objectStore(VAULTS).put(vault);
  });
}

/** Deletes everything this device holds for the account. */
export async function forgetAccount(id: string): Promise<void> {
  await transaction(ACCOUNT_STORES, "readwrite", (tx) => {
    for (const name of ACCOUNT_STORES) tx.objectStore(name).delete(id);
  });
}

/** Asks the browser not to clear this site's storage when the device runs low
 *  on space. Browsers may refuse; the data is then kept on a best-effort basis
 *  (installed iOS home screen apps are exempt from Safari's expiry anyway). */
export async function requestPersistentStorage(): Promise<void> {
  try {
    if (!(await navigator.storage?.persisted?.()))
      await navigator.storage?.persist?.();
  } catch {
    // not supported
  }
}
