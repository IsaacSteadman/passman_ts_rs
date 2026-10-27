// The extension's popup: unlocks the account on the user's Passman server,
// lists the logins for the current tab's site (and finds others), fills them
// into the page, and saves new ones in the user's own vault. Logins from
// shared vaults are checked the same way the web app checks them, and can be
// filled but not changed here.

import {
  decryptBlob,
  encryptBlob,
  fromBase64Url,
  initWasm,
  toBase64Url,
} from "../frontend/passman_crypto_glue";
import {
  credentialHeaders,
  decodeVault,
  describeError,
  downloadVault,
  unlockWithPassword,
} from "../frontend/loginArea";
import { setServerOrigin, serverUrl } from "../frontend/serverOrigin";
import type { PassTableData, VaultRoot } from "../frontend/PassTable";
import { generateOtp, otpSecondsRemaining } from "../frontend/mfa";
import { passgen } from "../frontend/passgen_util";
import { searchTerms } from "../frontend/vaultSearch";
import {
  OfflineError,
  SharedVault,
  SharingClient,
} from "../frontend/sharedVaultModel";
import { ext } from "./browserApi";
import {
  type Login,
  NEW_TABLE,
  loginHasTerms,
  loginMatches,
  loginTables,
  loginsIn,
  saveLogin,
  webSite,
} from "../frontend/logins";
import {
  type FillRequest,
  type FillResult,
  type TypedLogin,
  fillPage,
  readPage,
} from "./pageScripts";
import {
  type Settings,
  type StoredSession,
  type StoredSharedVault,
  LOCK_ALARM,
  clearSession,
  loadSession,
  loadSettings,
  saveSession,
  saveSettings,
  touchSession,
} from "./session";

const $ = <T extends Element>(selector: string) =>
  document.querySelector(selector) as T;

const lockedView = $<HTMLElement>("#locked");
const unlockedView = $<HTMLElement>("#unlocked");
const statusLine = $<HTMLElement>("#status");
const unlockForm = $<HTMLFormElement>("form[name=unlock]");
const field = (form: HTMLFormElement, name: string) =>
  form.querySelector(`[name=${name}]`) as HTMLInputElement;
const siteSpan = $<HTMLElement>("[name=site]");
const searchInput = $<HTMLInputElement>("input[name=search]");
const listTitle = $<HTMLElement>("[name=list-title]");
const loginList = $<HTMLUListElement>("ul[name=logins]");
const saveDetails = $<HTMLDetailsElement>("details[name=save]");
const saveForm = $<HTMLFormElement>("form[name=save-login]");
const saveUsername = field(saveForm, "save-username");
const savePassword = field(saveForm, "save-password");
const saveTable = $<HTMLSelectElement>("select[name=save-table]");
const lockMinutesSelect = $<HTMLSelectElement>("select[name=lock-minutes]");
const openApp = $<HTMLAnchorElement>("a[name=open-app]");

/** Opened as a page (e.g. by the tests) with the tab to work on. */
const params = new URLSearchParams(location.search);

let settings: Settings;
let session: StoredSession | null = null;
let vault: VaultRoot | null = null;
let sharedTables = new Map<string, PassTableData[]>();
let tab: chrome.tabs.Tab | null = null;
/** The page in the tab, if logins can be filled into it. */
let page: URL | null = null;

function setStatus(text: string): void {
  statusLine.textContent = text;
}

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className = "",
  text?: string,
): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (className) e.className = className;
  if (text != null) e.textContent = text;
  return e;
}

function button(label: string, primary = false): HTMLButtonElement {
  const b = el(
    "button",
    primary ? "pm-btn pm-btn-primary" : "pm-btn pm-btn-ghost",
    label,
  );
  b.type = "button";
  return b;
}

// ── Session ───────────────────────────────────────────────────────────────

const key = () => fromBase64Url(session!.encryptionKey);

function sealTables(tables: PassTableData[]): string {
  return toBase64Url(
    encryptBlob(key(), new TextEncoder().encode(JSON.stringify(tables))),
  );
}

function openTables(sealed: string): PassTableData[] {
  return JSON.parse(
    new TextDecoder().decode(decryptBlob(key(), fromBase64Url(sealed))),
  ) as PassTableData[];
}

/** Opens the session kept since the popup was last open. */
function resume(stored: StoredSession): void {
  session = stored;
  setServerOrigin(stored.server);
  vault = decodeVault(key(), fromBase64Url(stored.vault));
  sharedTables = new Map(
    stored.shared.map((s) => [s.id, openTables(s.tables)]),
  );
}

async function lock(message = ""): Promise<void> {
  session = null;
  vault = null;
  sharedTables = new Map();
  await clearSession();
  await ext.alarms.clear(LOCK_ALARM);
  showLocked();
  setStatus(message);
}

/** Brings the vault and shared vaults up to date with the server. */
async function refresh(): Promise<void> {
  const current = session;
  if (current == null) return;
  const download = await downloadVault(
    current.username,
    current.serverNs,
    current.serverPass,
    current.authKeyB64,
  );
  if (session !== current) return;
  if (!download.ok) {
    if (download.reason === "credentials")
      await lock(
        "The password was changed in another session. Unlock with the new one.",
      );
    else if (download.reason === "offline")
      setStatus("Offline: these are the logins from when you unlocked.");
    else setStatus(`Couldn't update ${download.message}`);
    return;
  }
  if (download.etag !== current.etag) {
    vault = decodeVault(key(), download.blob);
    current.vault = toBase64Url(download.blob);
    current.etag = download.etag;
    await saveSession(current);
    render();
  }
  await refreshShared(current);
}

/** "{epoch}-{version}" as numbers. */
function parseEtag(etag: string): [number, number] {
  const [epoch, version] = etag.replace(/"/g, "").split("-").map(Number);
  return [epoch, version];
}

function olderThan(etag: string, than: string): boolean {
  const [e1, v1] = parseEtag(etag);
  const [e2, v2] = parseEtag(than);
  return e1 < e2 || (e1 === e2 && v1 < v2);
}

async function refreshShared(current: StoredSession): Promise<void> {
  const sharing = vault?.sharing;
  if (sharing == null) {
    current.shared = [];
    return;
  }
  const client = new SharingClient({
    session: () => current,
    sharing: () => sharing,
    cacheAccount: () => null,
  });
  let infos;
  try {
    infos = await client.listVaults();
  } catch (e) {
    if (!(e instanceof OfflineError))
      setStatus(`Couldn't list shared vaults: ${e}`);
    return;
  }
  const problems: string[] = [];
  const next: StoredSharedVault[] = [];
  for (const info of infos) {
    const cached = current.shared.find((s) => s.id === info.id);
    if (cached && cached.etag === info.etag) {
      next.push(cached);
      continue;
    }
    if (cached && olderThan(info.etag, cached.etag)) {
      problems.push(
        `the server sent an older version of "${cached.name}", so it wasn't updated`,
      );
      next.push(cached);
      continue;
    }
    try {
      const shared = await SharedVault.download(client, info);
      next.push({
        id: info.id,
        name: shared.data.name,
        etag: info.etag,
        tables: sealTables(shared.data.tables),
        unverifiedManagers: shared.unverifiedManagers(sharing.contacts),
      });
    } catch (e) {
      problems.push(
        `couldn't load ${cached ? `"${cached.name}"` : "a shared vault"}: ${e instanceof Error ? e.message : e}`,
      );
      if (cached) next.push(cached);
    }
  }
  if (session !== current) return;
  current.shared = next;
  sharedTables = new Map(next.map((s) => [s.id, openTables(s.tables)]));
  await saveSession(current);
  render();
  if (problems.length > 0) setStatus(`⚠ Shared vaults: ${problems.join("; ")}`);
}

// ── Unlocking ─────────────────────────────────────────────────────────────

function showLocked(): void {
  unlockedView.hidden = true;
  lockedView.hidden = false;
  field(unlockForm, "server").value = settings.server;
  field(unlockForm, "username").value = settings.username;
  field(unlockForm, "server_pass").value = settings.serverPass;
  field(unlockForm, "server_ns").value = settings.serverNs;
  field(unlockForm, settings.username ? "password" : "server").focus();
}

/** The origin of the server address typed, which may lack "https://". */
function serverOrigin(text: string): string | null {
  const trimmed = text.trim();
  try {
    const url = new URL(
      /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`,
    );
    return url.protocol === "https:" || url.protocol === "http:"
      ? url.origin
      : null;
  } catch {
    return null;
  }
}

unlockForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const origin = serverOrigin(field(unlockForm, "server").value);
  if (origin == null) {
    setStatus("That isn't a server address.");
    return;
  }
  const submit = unlockForm.querySelector("button")!;
  submit.disabled = true;
  try {
    // asked first: Firefox only shows the request while handling the click
    const allowed = await ext.permissions.request({ origins: [`${origin}/*`] });
    if (!allowed) {
      setStatus("Passman needs permission to reach your server.");
      return;
    }
    setStatus("Unlocking…");
    const username = field(unlockForm, "username").value;
    const serverPass = field(unlockForm, "server_pass").value;
    const serverNs = field(unlockForm, "server_ns").value;
    setServerOrigin(origin);
    const result = await unlockWithPassword(
      username,
      serverNs || null,
      serverPass,
      field(unlockForm, "password").value,
      false,
    );
    if (typeof result === "string") {
      setStatus(result);
      return;
    }
    field(unlockForm, "password").value = "";
    settings = { ...settings, server: origin, username, serverNs, serverPass };
    await saveSettings(settings);
    session = {
      server: origin,
      username,
      serverNs: serverNs || null,
      serverPass,
      authKeyB64: result.authKeyB64,
      encryptionKey: toBase64Url(result.encryptionKey),
      vault: toBase64Url(result.synced.blob),
      etag: result.synced.etag,
      shared: [],
    };
    vault = result.synced.data;
    sharedTables = new Map();
    await saveSession(session);
    await touchSession(settings.lockMinutes);
    setStatus("");
    showUnlocked();
    await refreshShared(session);
  } finally {
    submit.disabled = false;
  }
});

// ── The logins ────────────────────────────────────────────────────────────

function allLogins(): Login[] {
  if (vault == null || session == null) return [];
  const logins = loginsIn(vault.tables, { kind: "own" });
  for (const shared of session.shared) {
    const tables = sharedTables.get(shared.id) ?? [];
    logins.push(
      ...loginsIn(tables, {
        kind: "shared",
        vaultId: shared.id,
        name: shared.name,
      }),
    );
  }
  return logins;
}

function showUnlocked(): void {
  lockedView.hidden = true;
  unlockedView.hidden = false;
  siteSpan.textContent = page ? page.hostname : "No site in this tab";
  saveDetails.hidden = page == null;
  lockMinutesSelect.value = String(settings.lockMinutes);
  openApp.href = session!.server;
  render();
  searchInput.focus();
}

/** Stops the code countdowns of the logins shown. */
let stopTimers: (() => void)[] = [];

function render(): void {
  if (session == null || vault == null) return;
  for (const stop of stopTimers) stop();
  stopTimers = [];
  const terms = searchTerms(searchInput.value);
  const logins = allLogins();
  let shown: Login[];
  if (terms.length > 0) {
    shown = logins.filter((login) => loginHasTerms(login, terms)).slice(0, 50);
    listTitle.textContent =
      shown.length > 0 ? "Search results" : "Nothing found";
  } else if (page) {
    const site = page;
    shown = logins.filter((login) => loginMatches(login, site));
    listTitle.textContent =
      shown.length > 0
        ? `Logins for ${page.hostname}`
        : `No logins saved for ${page.hostname}`;
  } else {
    shown = [];
    listTitle.textContent = "Search for a login";
  }
  loginList.replaceChildren(...shown.map(renderLogin));
  refreshTableChoices();
}

function renderLogin(login: Login): HTMLLIElement {
  const item = el("li", "ext-login");
  const title = el("div", "ext-login-title");
  title.append(el("strong", "", login.name));
  if (login.source.kind === "shared") {
    const source = login.source;
    const stored = session?.shared.find((s) => s.id === source.vaultId);
    const unverified = stored?.unverifiedManagers ?? [];
    const badge = el(
      "span",
      unverified.length > 0 ? "ext-badge ext-unverified" : "ext-badge",
      unverified.length > 0 ? `⚠ ${source.name}` : source.name,
    );
    badge.title =
      unverified.length > 0
        ? `From the shared vault "${source.name}", managed by ${unverified.join(", ")}, whose identity you haven't verified`
        : `From the shared vault "${source.name}"`;
    title.append(badge);
  }
  item.append(title);
  if (login.username) item.append(el("div", "ext-username", login.username));

  const actions = el("div", "ext-actions");
  const canFill = page != null && loginMatches(login, page);
  if (canFill && (login.username || login.password)) {
    const fill = button("Fill", true);
    fill.addEventListener("click", () =>
      fillLogin({
        username: login.username || null,
        password: login.password || null,
        code: null,
        newPassword: false,
      }),
    );
    actions.append(fill);
  }
  if (login.username)
    actions.append(copyButton("Copy username", login.username));
  if (login.password)
    actions.append(copyButton("Copy password", login.password));
  item.append(actions);

  if (login.mfaKey) {
    const otp = el("div", "ext-actions ext-otp");
    const code = el("span", "ext-code");
    const remaining = el("span", "ext-remaining");
    let current = "";
    const update = async () => {
      try {
        current = await generateOtp(login.mfaKey);
        code.textContent = `${current.slice(0, 3)} ${current.slice(3)}`;
        remaining.textContent = `${otpSecondsRemaining()}s`;
      } catch {
        code.textContent = "Invalid MFA key";
      }
    };
    void update();
    const timer = setInterval(update, 1000);
    stopTimers.push(() => clearInterval(timer));
    const copy = button("Copy code");
    copy.addEventListener("click", () => void copyText(current, "Code"));
    otp.append(code, remaining, copy);
    if (canFill) {
      const fill = button("Fill code");
      fill.addEventListener("click", () =>
        fillLogin({
          username: null,
          password: null,
          code: current,
          newPassword: false,
        }),
      );
      otp.append(fill);
    }
    item.append(otp);
  }
  return item;
}

async function copyText(text: string, what: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    setStatus(`${what} copied.`);
  } catch (e) {
    setStatus(`Couldn't copy: ${e}`);
  }
}

function copyButton(label: string, text: string): HTMLButtonElement {
  const b = button(label);
  b.addEventListener("click", () =>
    copyText(
      text,
      label.replace(/^Copy /, "").replace(/^./, (c) => c.toUpperCase()),
    ),
  );
  return b;
}

searchInput.addEventListener("input", () => render());

// ── The page ──────────────────────────────────────────────────────────────

/** Runs `func` in the tab's page (its top frame). */
async function inPage<A extends unknown[], R>(
  func: (...args: A) => R,
  ...args: A
): Promise<R> {
  if (tab?.id == null) throw new Error("no tab");
  const [result] = await ext.scripting.executeScript({
    target: { tabId: tab.id },
    func,
    args,
  });
  return result.result as R;
}

async function fillLogin(request: Omit<FillRequest, "origin">): Promise<void> {
  if (page == null) return;
  let result: FillResult;
  try {
    result = await inPage(fillPage, { ...request, origin: page.origin });
  } catch (e) {
    setStatus(`Couldn't fill this page: ${e}`);
    return;
  }
  if (result.error) {
    setStatus(result.error);
    return;
  }
  if (result.filled.length === 0) {
    setStatus("No field to fill was found on this page.");
    return;
  }
  setStatus(`Filled the ${result.filled.join(" and ")}.`);
  // a popup is done; a page opened for a tab stays
  if (!params.has("tab")) window.close();
}

// ── Saving ────────────────────────────────────────────────────────────────

function refreshTableChoices(): void {
  if (vault == null) return;
  const selected = saveTable.value;
  const options = loginTables(vault).map((table) => {
    const option = el("option", "", table.name);
    option.value = table.id;
    return option;
  });
  const fresh = el("option", "", "New table: Logins");
  fresh.value = NEW_TABLE;
  saveTable.replaceChildren(...options, fresh);
  if ([...saveTable.options].some((o) => o.value === selected))
    saveTable.value = selected;
}

$<HTMLButtonElement>("button[name=read-page]").addEventListener(
  "click",
  async () => {
    let typed: TypedLogin | null;
    try {
      typed = await inPage(readPage);
    } catch (e) {
      setStatus(`Couldn't read this page: ${e}`);
      return;
    }
    if (typed == null || typed.origin !== page?.origin) {
      setStatus("No password is typed on this page.");
      return;
    }
    saveUsername.value = typed.username;
    savePassword.value = typed.password;
    setStatus("");
  },
);

$<HTMLButtonElement>("button[name=show-password]").addEventListener(
  "click",
  (event) => {
    const shown = savePassword.type === "text";
    savePassword.type = shown ? "password" : "text";
    (event.currentTarget as HTMLButtonElement).textContent = shown
      ? "Show"
      : "Hide";
  },
);

$<HTMLButtonElement>("button[name=generate]").addEventListener("click", () => {
  savePassword.value = passgen(
    {
      symbols: "!#$%&*+-=?@^_",
      lettersAllowed: "all",
      mustUpper: true,
      mustLower: true,
      mustDigit: true,
      mustSymbol: true,
      canSpaces: false,
    },
    { type: "nchars", nChars: 20 },
  );
  savePassword.type = "text";
});

$<HTMLButtonElement>("button[name=fill-generated]").addEventListener(
  "click",
  () => {
    if (!savePassword.value) {
      setStatus("Generate or type a password first.");
      return;
    }
    void fillLogin({
      username: saveUsername.value || null,
      password: savePassword.value,
      code: null,
      newPassword: true,
    });
  },
);

/** Saves `change` in the vault, merging with any newer version on the
 *  server by applying it to that one instead. */
async function saveVault(change: (data: VaultRoot) => string): Promise<string> {
  for (let attempt = 0; attempt < 3; attempt++) {
    const current = session;
    if (current == null || vault == null) return "Locked.";
    const data = structuredClone(vault);
    const done = change(data);
    const json = JSON.stringify(data);
    const blob = encryptBlob(key(), new TextEncoder().encode(json));
    const url = serverUrl("/pass-table");
    url.searchParams.set("username", current.username);
    if (current.serverNs != null)
      url.searchParams.set("server_ns", current.serverNs);
    const headers: Record<string, string> = {
      ...credentialHeaders(current.authKeyB64, current.serverPass),
      "Content-Type": "application/octet-stream",
    };
    if (current.etag != null) headers["If-Match"] = current.etag;
    let response: Response;
    try {
      response = await fetch(url, { method: "PUT", headers, body: blob });
    } catch {
      return "Can't reach the server, so nothing was saved.";
    }
    if (response.status === 412) {
      // saved elsewhere since: start again from that version
      const latest = await downloadVault(
        current.username,
        current.serverNs,
        current.serverPass,
        current.authKeyB64,
      );
      if (!latest.ok) return `Couldn't save ${latest.message}`;
      vault = decodeVault(key(), latest.blob);
      current.vault = toBase64Url(latest.blob);
      current.etag = latest.etag;
      continue;
    }
    if (!response.ok) {
      const error = await describeError(response);
      if (error.type === "E_AUTH") {
        await lock(
          "The password was changed in another session. Unlock with the new one.",
        );
        return "";
      }
      return `Couldn't save ${error.message}`;
    }
    vault = data;
    current.vault = toBase64Url(blob);
    current.etag = response.headers.get("ETag");
    await saveSession(current);
    render();
    return done;
  }
  return "Couldn't save: the vault keeps changing in another session.";
}

saveForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const site = page;
  if (site == null) return;
  const submit =
    saveForm.querySelector<HTMLButtonElement>("button[name=save]")!;
  submit.disabled = true;
  setStatus("Saving…");
  try {
    const login = {
      site: webSite(site),
      username: saveUsername.value.trim(),
      password: savePassword.value,
    };
    const tableId = saveTable.value;
    setStatus(
      await saveVault((data) =>
        saveLogin(data, login, tableId).updated
          ? `Changed the password for ${login.username || site.hostname}.`
          : `Saved the login for ${site.hostname}.`,
      ),
    );
    if (session != null) {
      saveUsername.value = "";
      savePassword.value = "";
      savePassword.type = "password";
    }
  } finally {
    submit.disabled = false;
  }
});

// ── Settings ──────────────────────────────────────────────────────────────

$<HTMLButtonElement>("button[name=lock]").addEventListener("click", () =>
  lock(),
);

lockMinutesSelect.addEventListener("change", async () => {
  settings = { ...settings, lockMinutes: Number(lockMinutesSelect.value) };
  await saveSettings(settings);
  await touchSession(settings.lockMinutes);
});

// ── Starting ──────────────────────────────────────────────────────────────

async function start(): Promise<void> {
  await initWasm();
  settings = await loadSettings();
  const tabId = params.get("tab");
  tab =
    tabId != null
      ? await ext.tabs.get(Number(tabId))
      : ((await ext.tabs.query({ active: true, currentWindow: true }))[0] ??
        null);
  try {
    const url = new URL(tab?.url ?? "");
    page = url.protocol === "https:" || url.protocol === "http:" ? url : null;
  } catch {
    page = null;
  }

  const stored = await loadSession();
  if (stored == null) {
    showLocked();
    return;
  }
  try {
    resume(stored);
  } catch (e) {
    await lock(`Locked: ${e}`);
    return;
  }
  await touchSession(settings.lockMinutes);
  showUnlocked();
  await refresh();
}

void start();
