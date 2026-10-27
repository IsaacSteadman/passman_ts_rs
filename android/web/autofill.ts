// The Android app's autofill screen. When the user picks Passman in a login
// form of another app or a browser, Android opens this (AutofillActivity) to
// unlock an account remembered on this device and fill a login; after a form
// was sent, to save what was typed in it. It works offline, like the web
// app's lock screen: the vault (and shared vaults) are the copies kept on the
// device.
//
// What the login is for comes from the app, which checked it: a web page only
// when a known browser (by its signing certificate) reported it, otherwise the
// app's package name and signing certificate. Logins are only offered where
// they match that, as in the extensions; a login can be linked to an app once
// the user confirms it, after the app checked whether the login's site lists
// the app as its own (Digital Asset Links).

import { encryptBlob, initWasm } from "../../frontend/passman_crypto_glue";
import { initTheme } from "../../frontend/theme";
import {
  credentialHeaders,
  decodeVault,
  describeError,
  downloadVault,
  unlockWithKeys,
  unlockWithPassword,
  type LoginResult,
} from "../../frontend/loginArea";
import {
  listAccounts,
  listSharedVaults,
  putVault,
  type RememberedAccount,
} from "../../frontend/deviceStore";
import { keyProtector, unlockErrorMessage } from "../../frontend/keyProtector";
import { callNative, startNativeApp } from "../../frontend/nativeApp";
import { serverFetch, serverUrl } from "../../frontend/serverOrigin";
import { SharedVault, SharingClient } from "../../frontend/sharedVaultModel";
import type { VaultRoot } from "../../frontend/PassTable";
import { generateOtp } from "../../frontend/mfa";
import { searchTerms } from "../../frontend/vaultSearch";
import {
  addLink,
  appLink,
  appSite,
  loginHasTerms,
  loginTables,
  loginsIn,
  NEW_TABLE,
  saveLogin,
  webSite,
  type Login,
  type Site,
} from "../../frontend/logins";

interface AutofillContext {
  mode: "fill" | "save";
  target:
    | { kind: "web"; url: string }
    | { kind: "app"; packageName: string; certHash: string; label: string };
  /** The kinds of fields the form has. */
  fields: { username: boolean; password: boolean; otp: boolean };
  /** What was typed, when saving. */
  save: { username: string; password: string } | null;
}

const $ = <T extends Element>(selector: string) =>
  document.querySelector(selector) as T;

const targetLine = $<HTMLElement>("[name=target]");
const lockedSection = $<HTMLElement>("section[name=locked]");
const noAccounts = $<HTMLElement>("[name=no-accounts]");
const unlockForm = $<HTMLFormElement>("form[name=unlock]");
const accountSelect = $<HTMLSelectElement>("select[name=account]");
const biometricButton = $<HTMLButtonElement>("button[name=biometric]");
const passwordInput = $<HTMLInputElement>("input[name=password]");
const fillSection = $<HTMLElement>("section[name=fill]");
const listTitle = $<HTMLElement>("[name=list-title]");
const loginList = $<HTMLUListElement>("ul[name=logins]");
const searchInput = $<HTMLInputElement>("input[name=search]");
const resultList = $<HTMLUListElement>("ul[name=results]");
const saveSection = $<HTMLElement>("section[name=save]");
const saveSummary = $<HTMLElement>("[name=save-summary]");
const saveForm = $<HTMLFormElement>("form[name=save-login]");
const saveTableLabel = $<HTMLElement>("[name=save-table-label]");
const saveTable = $<HTMLSelectElement>("select[name=save-table]");
const statusLine = $<HTMLElement>("#status");
const closeButton = $<HTMLButtonElement>("button[name=close]");

let context: AutofillContext;
let site: Site;
let accounts: RememberedAccount[] = [];
let account: RememberedAccount | null = null;
let unlocked: LoginResult | null = null;
/** The user's own vault as of unlocking (with this device's unsaved
 *  changes). */
let ownVault: VaultRoot | null = null;
let logins: Login[] = [];
/** Shared vaults' managers whose identity the user hasn't verified. */
const unverified = new Map<string, string[]>();

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

function targetName(): string {
  const target = context.target;
  return target.kind === "web"
    ? new URL(target.url).hostname
    : `${target.label} (app)`;
}

// ── Unlocking ─────────────────────────────────────────────────────────────

async function showAccount(): Promise<void> {
  account = accounts.find((a) => a.id === accountSelect.value) ?? null;
  biometricButton.hidden = true;
  if (account == null) return;
  const id = account.id;
  const [supported, status] = await Promise.all([
    keyProtector.isSupported(),
    keyProtector.status(id).catch(() => null),
  ]);
  if (account?.id === id)
    biometricButton.hidden = !(supported && status?.current);
}

async function finishUnlock(result: LoginResult | string): Promise<void> {
  if (typeof result === "string") {
    setStatus(result);
    return;
  }
  if (account == null) return;
  unlocked = result;
  passwordInput.value = "";
  setStatus("");
  ownVault = structuredClone(result.pending ?? result.synced.data);
  logins = loginsIn(ownVault.tables, { kind: "own" });
  const sharing = ownVault.sharing;
  if (sharing != null) {
    const session = {
      username: result.username,
      serverNs: result.serverNs,
      serverPass: result.serverPass,
      authKeyB64: result.authKeyB64,
    };
    const client = new SharingClient({
      session: () => session,
      sharing: () => sharing,
      cacheAccount: () => null,
    });
    for (const cached of await listSharedVaults(account.id)) {
      try {
        const vault = SharedVault.fromCache(client, cached);
        unverified.set(vault.id, vault.unverifiedManagers(sharing.contacts));
        logins.push(
          ...loginsIn(vault.data.tables, {
            kind: "shared",
            vaultId: vault.id,
            name: vault.data.name,
          }),
        );
      } catch (e) {
        setStatus(`Couldn't open a shared vault: ${e}`);
      }
    }
  }
  lockedSection.hidden = true;
  if (context.mode === "fill") showFill();
  else showSave();
}

async function unlockWithBiometrics(): Promise<void> {
  const current = account;
  if (current == null) return;
  setStatus("");
  try {
    const keys = await keyProtector.unlock(current.id);
    await finishUnlock(
      await unlockWithKeys(
        current.username,
        current.serverNs,
        current.serverPass,
        keys,
        true,
      ),
    );
  } catch (e) {
    setStatus(unlockErrorMessage(e));
    void showAccount();
  }
}

biometricButton.addEventListener("click", () => void unlockWithBiometrics());

unlockForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const current = account;
  if (current == null || !passwordInput.value) return;
  const submit = unlockForm.querySelector<HTMLButtonElement>(
    "button[name=unlock]",
  )!;
  submit.disabled = true;
  setStatus("Unlocking…");
  try {
    await finishUnlock(
      await unlockWithPassword(
        current.username,
        current.serverNs,
        current.serverPass,
        passwordInput.value,
        true,
      ),
    );
  } finally {
    submit.disabled = false;
  }
});

accountSelect.addEventListener("change", () => void showAccount());

// ── Filling ───────────────────────────────────────────────────────────────

async function fill(login: Login): Promise<void> {
  const otp =
    context.fields.otp && login.mfaKey ? await generateOtp(login.mfaKey) : "";
  await callNative("autofillFill", {
    username: login.username,
    password: login.password,
    otp,
  });
}

function renderLogin(login: Login, matching: boolean): HTMLLIElement {
  const item = el("li", "af-login");
  const title = el("div", "af-login-title");
  title.append(el("strong", "", login.name));
  if (login.source.kind === "shared") {
    const managers = unverified.get(login.source.vaultId) ?? [];
    const badge = el(
      "span",
      managers.length > 0 ? "af-badge af-unverified" : "af-badge",
      managers.length > 0 ? `⚠ ${login.source.name}` : login.source.name,
    );
    badge.title =
      managers.length > 0
        ? `From the shared vault "${login.source.name}", managed by ${managers.join(", ")}, whose identity you haven't verified`
        : `From the shared vault "${login.source.name}"`;
    title.append(badge);
  }
  item.append(title);
  if (login.username) item.append(el("p", "af-username", login.username));
  const actions = el("div", "af-actions");
  item.append(actions);
  if (matching) {
    const fillButton = button("Fill", true);
    fillButton.addEventListener("click", () => void fill(login));
    actions.append(fillButton);
  } else if (context.target.kind === "app") {
    const linkButton = button("Use for this app…");
    linkButton.addEventListener(
      "click",
      () => void confirmLink(login, item, actions),
    );
    actions.append(linkButton);
  } else {
    // as in the extensions: a login saved for another site is never filled
    // into this page, which may imitate that site
    const saved = login.urls[0] ?? "";
    item.append(
      el(
        "p",
        "af-note",
        saved
          ? `Saved for ${saved}, so it isn't filled here.`
          : "It has no site, so it isn't filled here.",
      ),
    );
  }
  return item;
}

/** Asks before filling a login into an app it isn't linked to, saying
 *  whether the login's sites list the app as their own. */
async function confirmLink(
  login: Login,
  item: HTMLLIElement,
  actions: HTMLElement,
): Promise<void> {
  const target = context.target;
  if (target.kind !== "app") return;
  actions.replaceChildren(el("p", "af-note", "Checking…"));
  const sites = login.urls.filter((url) => /^https:\/\//i.test(url.trim()));
  let verified: string[] = [];
  try {
    ({ verified } = await callNative<{ verified: string[] }>("checkAppLinks", {
      urls: sites,
    }));
  } catch {
    // treated as unconfirmed
  }
  const note =
    verified.length > 0
      ? el(
          "p",
          "af-note",
          `✓ ${verified.join(", ")} lists ${target.label} as its app.`,
        )
      : el(
          "p",
          "af-note af-warning",
          `⚠ ${sites.length > 0 ? "None of this login's sites list" : "This login has no site that could confirm"} ${target.label} (${target.packageName}) as its app. Fill it only if you're sure this is the real app.`,
        );
  const own = login.source.kind === "own";
  const confirm = button(own ? "Fill and remember for this app" : "Fill", true);
  confirm.addEventListener(
    "click",
    async () => {
      if (own) {
        confirm.disabled = true;
        const saved = await saveOwnVault((data) => {
          addLink(data, login, appLink(target));
        });
        if (!saved.ok) {
          setStatus(saved.message);
          confirm.textContent = "Fill without remembering";
          confirm.disabled = false;
          confirm.addEventListener("click", () => void fill(login), {
            once: true,
          });
          return;
        }
      }
      await fill(login);
    },
    { once: true },
  );
  const cancel = button("Cancel");
  cancel.addEventListener("click", () => {
    item.replaceWith(renderLogin(login, false));
  });
  actions.replaceChildren(note, confirm, cancel);
}

function showFill(): void {
  fillSection.hidden = false;
  const matches = logins.filter((login) => site.matches(login));
  listTitle.textContent =
    matches.length > 0
      ? `Logins for ${targetName()}`
      : `No logins saved for ${targetName()}`;
  loginList.replaceChildren(...matches.map((l) => renderLogin(l, true)));
  searchInput.focus();
}

searchInput.addEventListener("input", () => {
  const terms = searchTerms(searchInput.value);
  const found =
    terms.length === 0
      ? []
      : logins
          .filter((l) => !site.matches(l) && loginHasTerms(l, terms))
          .slice(0, 50);
  resultList.replaceChildren(...found.map((l) => renderLogin(l, false)));
});

// ── Saving ────────────────────────────────────────────────────────────────

function showSave(): void {
  const vault = ownVault;
  const typed = context.save;
  if (vault == null || typed == null) return;
  saveSection.hidden = false;
  const existing = logins.find(
    (l) =>
      l.source.kind === "own" &&
      l.username === typed.username &&
      l.password !== "" &&
      site.matches(l),
  );
  const who = typed.username || "the login";
  if (existing?.password === typed.password) {
    saveSummary.textContent = `${who} for ${targetName()} is already saved.`;
    saveForm.hidden = true;
    closeButton.textContent = "Done";
    return;
  }
  saveSummary.textContent = existing
    ? `Change the saved password of ${who} for ${targetName()}?`
    : `Save ${who} for ${targetName()}?`;
  saveTableLabel.hidden = existing != null;
  const tables = loginTables(vault);
  saveTable.replaceChildren(
    ...tables.map((t) => new Option(t.name, t.id)),
    new Option("A new table “Logins”", NEW_TABLE),
  );
}

saveForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const typed = context.save;
  if (typed == null) return;
  const submit =
    saveForm.querySelector<HTMLButtonElement>("button[name=save]")!;
  submit.disabled = true;
  setStatus("Saving…");
  const tableId = saveTable.value;
  let updated = false;
  const saved = await saveOwnVault((data) => {
    updated = saveLogin(data, { site, ...typed }, tableId).updated;
  });
  if (!saved.ok) {
    setStatus(saved.message);
    submit.disabled = false;
    return;
  }
  setStatus(
    saved.onDevice
      ? SAVED_ON_DEVICE
      : updated
        ? `Changed the password for ${typed.username || targetName()}.`
        : `Saved the login for ${targetName()}.`,
  );
  saveForm.hidden = true;
  closeButton.textContent = "Done";
});

/** Message for a save that only reached this device. */
const SAVED_ON_DEVICE =
  "Saved on this device; Passman uploads it the next time it's open online.";

type SaveResult =
  | { ok: true; /** Only on this device so far. */ onDevice: boolean }
  | { ok: false; message: string };

const PASSWORD_CHANGED: SaveResult = {
  ok: false,
  message:
    "The password was changed in another session: open Passman to finish that first.",
};

/**
 * Applies `change` to the user's own vault and saves it on the server (and
 * this device). Offline, or when this device has changes that aren't on the
 * server yet, the change is kept with those on the device, for the app to
 * upload.
 */
async function saveOwnVault(
  change: (data: VaultRoot) => void,
): Promise<SaveResult> {
  const result = unlocked;
  const current = account;
  if (result == null || current == null)
    return { ok: false, message: "Locked." };
  if (result.keysChanged) return PASSWORD_CHANGED;
  const key = result.encryptionKey;
  const keepOnDevice = async (data: VaultRoot) => {
    await putVault({
      id: current.id,
      syncedBlob: result.synced.blob,
      syncedEtag: result.synced.etag,
      syncedLastModified: result.synced.lastModified,
      pendingBlob: encryptBlob(
        key,
        new TextEncoder().encode(JSON.stringify(data)),
      ),
    });
    result.pending = data;
    ownVault = structuredClone(data);
  };
  if (result.pending != null) {
    const data = structuredClone(result.pending);
    change(data);
    await keepOnDevice(data);
    return { ok: true, onDevice: true };
  }
  for (let attempt = 0; attempt < 3; attempt++) {
    const data = structuredClone(result.synced.data);
    change(data);
    const blob = encryptBlob(
      key,
      new TextEncoder().encode(JSON.stringify(data)),
    );
    const url = serverUrl("/pass-table");
    url.searchParams.set("username", result.username);
    if (result.serverNs != null)
      url.searchParams.set("server_ns", result.serverNs);
    const headers: Record<string, string> = {
      ...credentialHeaders(result.authKeyB64, result.serverPass),
      "Content-Type": "application/octet-stream",
    };
    if (result.synced.etag != null) headers["If-Match"] = result.synced.etag;
    let response: Response;
    try {
      response = await serverFetch(url, { method: "PUT", headers, body: blob });
    } catch {
      await keepOnDevice(data);
      return { ok: true, onDevice: true };
    }
    if (response.status === 412) {
      // saved elsewhere since: start again from that version
      const latest = await downloadVault(
        result.username,
        result.serverNs,
        result.serverPass,
        result.authKeyB64,
      );
      if (!latest.ok)
        return { ok: false, message: `Couldn't save ${latest.message}` };
      try {
        result.synced = {
          data: decodeVault(key, latest.blob),
          blob: latest.blob,
          etag: latest.etag,
          lastModified: latest.lastModified,
        };
      } catch {
        return PASSWORD_CHANGED;
      }
      continue;
    }
    if (!response.ok) {
      const error = await describeError(response);
      return error.type === "E_AUTH"
        ? PASSWORD_CHANGED
        : { ok: false, message: `Couldn't save ${error.message}` };
    }
    result.synced = {
      data,
      blob,
      etag: response.headers.get("ETag"),
      lastModified: response.headers.get("Last-Modified"),
    };
    await putVault({
      id: current.id,
      syncedBlob: blob,
      syncedEtag: result.synced.etag,
      syncedLastModified: result.synced.lastModified,
      pendingBlob: null,
    });
    ownVault = structuredClone(data);
    return { ok: true, onDevice: false };
  }
  return {
    ok: false,
    message: "Couldn't save: the vault keeps changing in another session.",
  };
}

// ── Starting ──────────────────────────────────────────────────────────────

closeButton.addEventListener("click", () => void callNative("autofillDone"));

async function start(): Promise<void> {
  initTheme();
  await initWasm();
  await startNativeApp();
  context = await callNative<AutofillContext>("autofillContext");
  const target = context.target;
  site =
    target.kind === "web"
      ? webSite(new URL(target.url))
      : appSite(target, target.label);
  targetLine.textContent =
    context.mode === "fill"
      ? `Fill into ${targetName()}`
      : `Save a login for ${targetName()}`;
  accounts = await listAccounts();
  if (accounts.length === 0) {
    noAccounts.hidden = false;
    return;
  }
  accountSelect.replaceChildren(
    ...accounts.map(
      (a) =>
        new Option(
          a.serverNs ? `${a.username} (${a.serverNs})` : a.username,
          a.id,
        ),
    ),
  );
  unlockForm.hidden = false;
  await showAccount();
  // the check Android shows over this screen, unless biometrics aren't set
  // up for the account
  if (!biometricButton.hidden) void unlockWithBiometrics();
  else passwordInput.focus();
}

start().catch((e) => setStatus(`Couldn't start: ${e}`));
