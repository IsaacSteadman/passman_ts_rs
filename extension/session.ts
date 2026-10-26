// What the extension keeps between popups. The unlocked session lives in
// session storage, which browsers keep in memory only and clear when they
// close (and the background script clears when the extension locks); the
// settings, which hold no secrets, live in local storage.

import { ext } from "./browserApi";

export interface Settings {
  server: string;
  username: string;
  serverNs: string;
  serverPass: string;
  /** Lock after this many minutes without opening the extension; 0 only
   *  locks when the browser closes. */
  lockMinutes: number;
}

export const DEFAULT_SETTINGS: Settings = {
  server: "",
  username: "",
  serverNs: "",
  serverPass: "",
  lockMinutes: 15,
};

export async function loadSettings(): Promise<Settings> {
  const { settings } = await ext.storage.local.get("settings");
  return { ...DEFAULT_SETTINGS, ...(settings as Partial<Settings>) };
}

export async function saveSettings(settings: Settings): Promise<void> {
  await ext.storage.local.set({ settings });
}

/** A shared vault as last downloaded and checked. */
export interface StoredSharedVault {
  id: string;
  name: string;
  /** Its server ETag, "{epoch}-{version}", to tell when it changed (and to
   *  refuse older versions). */
  etag: string;
  /** Its tables, encrypted with the account's key. */
  tables: string;
  /** Managers whose identity the user hasn't verified. */
  unverifiedManagers: string[];
}

export interface StoredSession {
  server: string;
  username: string;
  serverNs: string | null;
  serverPass: string;
  authKeyB64: string;
  /** URL-safe base64, as are the blobs. */
  encryptionKey: string;
  /** The vault as the server holds it (encrypted), and its ETag. */
  vault: string;
  etag: string | null;
  shared: StoredSharedVault[];
}

/** Session storage needs Chrome 102, Firefox 115 or Safari 16.4; without it
 *  the extension locks whenever the popup closes. */
const sessionArea = (): chrome.storage.StorageArea | undefined =>
  ext.storage.session;

export async function loadSession(): Promise<StoredSession | null> {
  const area = sessionArea();
  if (area == null) return null;
  const { session } = await area.get("session");
  return (session as StoredSession | undefined) ?? null;
}

export async function saveSession(session: StoredSession): Promise<void> {
  await sessionArea()?.set({ session });
}

export async function clearSession(): Promise<void> {
  await sessionArea()?.remove("session");
}

export const LOCK_ALARM = "lock";

/** (Re)starts the countdown to locking. */
export async function touchSession(lockMinutes: number): Promise<void> {
  if (lockMinutes > 0)
    await ext.alarms.create(LOCK_ALARM, { delayInMinutes: lockMinutes });
  else await ext.alarms.clear(LOCK_ALARM);
}
