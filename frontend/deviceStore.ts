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

/** A shared vault kept on the device for a remembered account, so it can be
 *  opened and changed offline. Records and versions are as signed by their
 *  authors (and were checked before being stored); unsaved changes are
 *  encrypted with the key of the epoch they were made in. */
export interface CachedSharedVault {
  /** `sharedVaultCacheId(account, vaultId)` */
  id: string;
  account: string;
  vaultId: string;
  /** The vault's member list records, from the first. */
  records: Uint8Array[];
  /** The version last downloaded from or saved to the server. */
  synced: Uint8Array;
  /** This device's unsaved changes: the epoch whose key encrypts them, and
   *  the encrypted contents. */
  pending: { epoch: number; blob: Uint8Array } | null;
}

/** What biometric unlock stores for an account (see keyProtector.ts). The
 *  shape depends on the protector, so it's opaque here. */
export interface StoredUnlockKey {
  id: string;
}

const DB_NAME = "passman";
const DB_VERSION = 3;
const ACCOUNTS = "accounts";
const VAULTS = "vaults";
const UNLOCK_KEYS = "unlockKeys";
/** Keyed by vault, with an index on the account. */
const SHARED_VAULTS = "sharedVaults";

/** Every store holding per-account data, so forgetting an account clears all
 *  of it. */
const ACCOUNT_STORES = [ACCOUNTS, VAULTS, UNLOCK_KEYS];

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
      if (!db.objectStoreNames.contains(SHARED_VAULTS))
        db.createObjectStore(SHARED_VAULTS, { keyPath: "id" }).createIndex(
          "account",
          "account",
        );
    };
    request.onsuccess = () => {
      const db = request.result;
      // let a newer version of the app (e.g. in another tab) upgrade the
      // database; the next access here reopens it
      db.onversionchange = () => {
        db.close();
        dbPromise = null;
      };
      resolve(db);
    };
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

export async function getUnlockKey<T extends StoredUnlockKey>(
  id: string,
): Promise<T | undefined> {
  return transaction<T>([UNLOCK_KEYS], "readonly", (tx) =>
    tx.objectStore(UNLOCK_KEYS).get(id),
  );
}

export async function putUnlockKey(key: StoredUnlockKey): Promise<void> {
  await transaction([UNLOCK_KEYS], "readwrite", (tx) => {
    tx.objectStore(UNLOCK_KEYS).put(key);
  });
}

export async function deleteUnlockKey(id: string): Promise<void> {
  await transaction([UNLOCK_KEYS], "readwrite", (tx) => {
    tx.objectStore(UNLOCK_KEYS).delete(id);
  });
}

export function sharedVaultCacheId(account: string, vaultId: string): string {
  return JSON.stringify([account, vaultId]);
}

export async function listSharedVaults(
  account: string,
): Promise<CachedSharedVault[]> {
  const vaults = await transaction<CachedSharedVault[]>(
    [SHARED_VAULTS],
    "readonly",
    (tx) => tx.objectStore(SHARED_VAULTS).index("account").getAll(account),
  );
  return vaults ?? [];
}

export async function putSharedVault(vault: CachedSharedVault): Promise<void> {
  await transaction([SHARED_VAULTS], "readwrite", (tx) => {
    tx.objectStore(SHARED_VAULTS).put(vault);
  });
}

export async function deleteSharedVault(id: string): Promise<void> {
  await transaction([SHARED_VAULTS], "readwrite", (tx) => {
    tx.objectStore(SHARED_VAULTS).delete(id);
  });
}

/** Deletes everything this device holds for the account. */
export async function forgetAccount(id: string): Promise<void> {
  await transaction([...ACCOUNT_STORES, SHARED_VAULTS], "readwrite", (tx) => {
    for (const name of ACCOUNT_STORES) tx.objectStore(name).delete(id);
    const shared = tx.objectStore(SHARED_VAULTS);
    const keys = shared.index("account").getAllKeys(id);
    keys.onsuccess = () => {
      for (const key of keys.result) shared.delete(key);
    };
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
