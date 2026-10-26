// The Shared Vaults section: vaults that several users can open and edit
// (see src/shared_vaults.rs). As with the user's own vault, the server only
// sees ciphertext. Each shared vault is encrypted with its own random key; the
// server keeps that key sealed to each member's sharing key (an X25519 public
// key), whose secret half is kept in the member's own vault.

import type { Session } from "./contentArea";
import { credentialHeaders, decodeVault } from "./loginArea";
import { mergeVaults, vaultsEqual } from "./merge";
import {
  type HistoryEntry,
  type PassTableCallbacks,
  type PassTableData,
  type SharingKeys,
  type VaultRoot,
  renderPassTable,
} from "./PassTable";
import {
  decryptBlob,
  encryptBlob,
  fromBase64Url,
  generateSharingKeyPair,
  sealTo,
  toBase64Url,
  unsealWith,
  XCHACHA20_KEY_SIZE,
} from "./passman_crypto_glue";

export interface SharedVaultsPanelHandle {
  /** Loads the shared vaults (after unlocking). */
  show(): void;
  /** Forgets the vault keys and decrypted vaults (on locking). */
  clear(): void;
  /** Whether a change to a shared vault hasn't been saved yet. */
  hasUnsavedChanges(): boolean;
}

type Role = "Owner" | "Editor";

/** A shared vault as listed by the server (GET /shared-vaults). */
interface VaultInfo {
  id: string;
  role: Role;
  wrappedKey: string;
  encryptedName: string;
  members: { username: string; role: Role }[];
  size: number;
  maxDataSize: number | null;
  maxMembers: number;
  writable: boolean;
}

const HISTORY_LIMIT = 100;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** A short, readable digest of a sharing key, for checking out of band that
 *  the server handed out the right one. */
export async function fingerprint(publicKey: string): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", fromBase64Url(publicKey)),
  );
  const hex = Array.from(digest.subarray(0, 16), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
  return hex.match(/.{4}/g)!.join(" ");
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function button(
  label: string,
  className = "pm-btn pm-btn-ghost",
): HTMLButtonElement {
  const b = document.createElement("button");
  b.type = "button";
  b.className = className;
  b.textContent = label;
  return b;
}

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  e.className = className;
  if (text != null) e.textContent = text;
  return e;
}

export function initSharedVaultsPanel(
  getSession: () => Session | null,
  getSharingKeys: () => SharingKeys | null,
  setSharingKeys: (keys: SharingKeys) => Promise<boolean>,
): SharedVaultsPanelHandle {
  const panel = document.querySelector("#shared-vaults") as HTMLElement;
  const field = <T extends Element>(selector: string) =>
    panel.querySelector(selector) as T;
  const intro = field<HTMLElement>("[name='shared-intro']");
  const setupButton = field<HTMLButtonElement>("button[name='setup-sharing']");
  const fingerprintLine = field<HTMLElement>("[name='sharing-fingerprint']");
  const list = field<HTMLElement>("[name='shared-list']");
  const createForm = field<HTMLFormElement>("form[name='create-shared']");
  const createName = field<HTMLInputElement>("input[name='shared-name']");
  const status = field<HTMLElement>("[name='shared-status']");

  /** Bumped by `clear`, so requests from a locked session are ignored. */
  let generation = 0;
  const cards = new Map<string, VaultCard>();

  // ── Requests ──────────────────────────────────────────────────────────────

  /** Makes a request as the unlocked user; null if the server couldn't be
   *  reached (or the session ended meanwhile). */
  async function request(
    method: string,
    path: string,
    init: {
      query?: Record<string, string>;
      json?: unknown;
      body?: Uint8Array<ArrayBuffer>;
      headers?: Record<string, string>;
    } = {},
  ): Promise<Response | null> {
    const session = getSession();
    if (session == null) return null;
    const started = generation;
    const url = new URL(path, window.location.origin);
    url.searchParams.set("username", session.username);
    if (session.serverNs != null)
      url.searchParams.set("server_ns", session.serverNs);
    for (const [k, v] of Object.entries(init.query ?? {}))
      url.searchParams.set(k, v);
    const headers: Record<string, string> = {
      ...credentialHeaders(session.authKeyB64, session.serverPass),
      ...init.headers,
    };
    let body: BodyInit | undefined;
    if (init.json !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(init.json);
    } else if (init.body !== undefined) {
      headers["Content-Type"] = "application/octet-stream";
      body = init.body;
    }
    try {
      const response = await fetch(url.toString(), {
        method,
        headers,
        body,
        cache: "no-store",
      });
      return started === generation ? response : null;
    } catch {
      return null;
    }
  }

  /** The error to show for a failed request. */
  async function failure(
    response: Response | null,
    action: string,
  ): Promise<string> {
    if (response == null) return `⚠ Couldn't ${action}: can't reach the server`;
    const text = await response.text();
    try {
      const body = JSON.parse(text) as {
        message?: string;
        policy_message?: string;
      };
      const reason = body.policy_message ?? body.message;
      if (reason) return `⚠ Couldn't ${action}: ${reason}`;
    } catch {
      // not JSON
    }
    return `⚠ Couldn't ${action} (${response.status}): ${text}`;
  }

  // ── Sharing keys ──────────────────────────────────────────────────────────

  /** Makes sure the server has this user's sharing key, creating the key
   *  pair first if needed. Returns the keys, or an error to show. */
  async function ensureSharingKeys(): Promise<SharingKeys | string> {
    let keys = getSharingKeys();
    if (keys == null) {
      const existing = await request("GET", "/sharing-key");
      if (existing == null) return "⚠ Can't reach the server";
      if (existing.ok)
        return "Sharing was set up in another session. Reload the page to use it here.";
      const pair = generateSharingKeyPair();
      keys = {
        publicKey: toBase64Url(pair.publicKey),
        secretKey: toBase64Url(pair.secretKey),
      };
      // kept in the vault before it's published, so the secret key can't be
      // lost while others seal vault keys to it
      if (!(await setSharingKeys(keys)))
        return "⚠ Couldn't save your sharing key to your vault (see the status at the top). Try again once it's saved.";
    }
    const response = await request("PUT", "/sharing-key", {
      json: { publicKey: keys.publicKey },
    });
    if (response == null || !response.ok)
      return failure(response, "publish your sharing key");
    return keys;
  }

  async function renderSetup(): Promise<void> {
    const keys = getSharingKeys();
    setupButton.hidden = keys != null;
    createForm.hidden = keys == null;
    intro.textContent =
      keys == null
        ? "Share tables with other people. Setting up sharing creates a sharing key, kept in your vault, that others use to give you access to their shared vaults."
        : "Vaults you share with other people. Everyone in a shared vault can see and change its tables.";
    fingerprintLine.textContent =
      keys == null
        ? ""
        : `Your sharing key fingerprint: ${await fingerprint(keys.publicKey)}`;
  }

  setupButton.addEventListener("click", async () => {
    setupButton.disabled = true;
    status.textContent = "Setting up sharing…";
    try {
      const result = await ensureSharingKeys();
      status.textContent = typeof result === "string" ? result : "";
      await renderSetup();
    } finally {
      setupButton.disabled = false;
    }
  });

  // ── List ──────────────────────────────────────────────────────────────────

  async function refresh(): Promise<void> {
    const keys = getSharingKeys();
    if (keys == null) return;
    const response = await request("GET", "/shared-vaults");
    if (response == null || !response.ok) {
      status.textContent = await failure(response, "load shared vaults");
      return;
    }
    const { vaults } = (await response.json()) as { vaults: VaultInfo[] };
    const secretKey = fromBase64Url(keys.secretKey);
    const seen = new Set<string>();
    for (const info of vaults) {
      seen.add(info.id);
      const card = cards.get(info.id);
      if (card) card.update(info);
      else {
        const created = new VaultCard(info, secretKey);
        cards.set(info.id, created);
        list.append(created.details);
      }
    }
    for (const [id, card] of cards) {
      if (!seen.has(id)) {
        card.details.remove();
        cards.delete(id);
      }
    }
    if (status.textContent?.startsWith("⚠ Couldn't load"))
      status.textContent = "";
    renderEmpty();
  }

  function renderEmpty(): void {
    list.querySelector(".pm-empty-note")?.remove();
    if (cards.size === 0)
      list.append(
        el(
          "p",
          "pm-empty-note",
          "No shared vaults yet. Create one, or give someone your username to be added to theirs.",
        ),
      );
  }

  createForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const name = createName.value.trim();
    if (!name) {
      status.textContent = "Enter a name for the shared vault.";
      return;
    }
    const submit = createForm.querySelector("button") as HTMLButtonElement;
    submit.disabled = true;
    try {
      status.textContent = "Creating…";
      const keys = await ensureSharingKeys();
      if (typeof keys === "string") {
        status.textContent = keys;
        return;
      }
      const vaultKey = crypto.getRandomValues(
        new Uint8Array(XCHACHA20_KEY_SIZE),
      );
      const response = await request("POST", "/shared-vaults", {
        json: {
          encryptedName: toBase64Url(
            encryptBlob(vaultKey, encoder.encode(name)),
          ),
          wrappedKey: toBase64Url(
            sealTo(fromBase64Url(keys.publicKey), vaultKey),
          ),
          publicKey: keys.publicKey,
        },
      });
      if (response == null || !response.ok) {
        status.textContent = await failure(response, "create the shared vault");
        return;
      }
      const { id } = (await response.json()) as { id: string };
      createName.value = "";
      status.textContent = "";
      await refresh();
      const card = cards.get(id);
      if (card) card.details.open = true;
    } finally {
      submit.disabled = false;
    }
  });

  // ── One shared vault ──────────────────────────────────────────────────────

  class VaultCard {
    readonly details = el("details", "pm-chg-pass-details pm-shared-vault");
    private readonly summaryName = el("span", "pm-shared-name");
    private readonly summaryMeta = el("span", "pm-shared-meta");
    private readonly statusLine = el("p", "pm-chg-pass-status");
    private readonly tablesDiv = el("div", "pm-shared-tables");
    private readonly manageDiv = el("div", "pm-device-subsection");
    private info: VaultInfo;
    /** null when the vault key couldn't be unsealed */
    private key: Uint8Array | null = null;
    private name = "";
    /** This session's data, and the version last loaded or saved. */
    private data: VaultRoot | null = null;
    private base: VaultRoot | null = null;
    private etag: string | null = null;
    private queue: Promise<void> = Promise.resolve();
    private loading: Promise<void> | null = null;

    constructor(info: VaultInfo, secretKey: Uint8Array) {
      this.info = info;
      try {
        this.key = unsealWith(secretKey, fromBase64Url(info.wrappedKey));
      } catch {
        this.key = null;
      }
      const summary = document.createElement("summary");
      summary.append(this.summaryName, this.summaryMeta);
      const body = el("div", "pm-chg-pass-body");
      body.append(this.statusLine, this.tablesDiv, this.manageDiv);
      this.details.append(summary, body);
      this.details.addEventListener("toggle", () => {
        if (this.details.open) void this.load();
      });
      this.update(info);
    }

    update(info: VaultInfo): void {
      this.info = info;
      if (this.key) {
        try {
          this.name = decoder.decode(
            decryptBlob(this.key, fromBase64Url(info.encryptedName)),
          );
        } catch {
          this.name = "(unreadable name)";
        }
      } else this.name = "(can't be opened)";
      this.summaryName.textContent = this.name;
      const count = info.members.length;
      this.summaryMeta.textContent = `${info.role} · ${count} ${count === 1 ? "member" : "members"}`;
      this.renderManage();
    }

    hasUnsavedChanges(): boolean {
      return (
        this.data != null &&
        this.base != null &&
        !vaultsEqual(this.data, this.base)
      );
    }

    private setStatus(text: string): void {
      this.statusLine.textContent = text;
    }

    private showUsage(): void {
      const { size, maxDataSize, writable } = this.info;
      const usage =
        maxDataSize == null
          ? `Uses ${formatSize(size)}`
          : `Uses ${formatSize(size)} of ${formatSize(maxDataSize)}`;
      this.setStatus(
        writable
          ? usage
          : `${usage}. The server no longer allows changes to this vault.`,
      );
    }

    /** Downloads and decrypts the latest version, or returns an error. */
    private async download(): Promise<
      { data: VaultRoot; etag: string | null } | string
    > {
      if (this.key == null) return "No key";
      const response = await request(
        "GET",
        `/shared-vaults/${this.info.id}/data`,
      );
      if (response == null || !response.ok)
        return failure(response, "load the vault");
      const blob = new Uint8Array(await response.arrayBuffer());
      try {
        return {
          // a new vault is empty until its first save
          data:
            blob.byteLength === 0
              ? { tables: [], history: [] }
              : decodeVault(this.key, blob),
          etag: response.headers.get("ETag"),
        };
      } catch (e) {
        return `⚠ Couldn't decrypt the vault: ${e}`;
      }
    }

    private load(): Promise<void> {
      if (this.data != null) return Promise.resolve();
      if (this.key == null) {
        this.setStatus(
          "⚠ This vault's key was sealed to a different sharing key than yours, so it can't be opened. Ask an owner to add you again.",
        );
        return Promise.resolve();
      }
      this.loading ??= (async () => {
        this.setStatus("Loading…");
        const latest = await this.download();
        this.loading = null;
        if (typeof latest === "string") {
          this.setStatus(latest);
          return;
        }
        this.base = latest.data;
        this.data = structuredClone(latest.data);
        this.etag = latest.etag;
        this.showUsage();
        this.render();
      })();
      return this.loading;
    }

    // ── Saving ──────────────────────────────────────────────────────────────

    private record(entry: HistoryEntry): Promise<void> {
      if (this.data == null) return Promise.resolve();
      this.data.history.push(entry);
      if (this.data.history.length > HISTORY_LIMIT)
        this.data.history.splice(0, this.data.history.length - HISTORY_LIMIT);
      return this.save();
    }

    private save(): Promise<void> {
      this.queue = this.queue.then(() => this.saveNow());
      return this.queue;
    }

    private async saveNow(): Promise<void> {
      // a save refused because someone else saved first is retried after
      // merging their changes
      for (let attempt = 0; attempt < 3; attempt++) {
        if (this.data == null || this.key == null) return;
        if (!this.hasUnsavedChanges()) return;
        this.setStatus("Saving…");
        const json = JSON.stringify(this.data);
        const blob = encryptBlob(this.key, encoder.encode(json));
        const headers: Record<string, string> = {};
        if (this.etag != null) headers["If-Match"] = this.etag;
        const response = await request(
          "PUT",
          `/shared-vaults/${this.info.id}/data`,
          { body: blob, headers },
        );
        if (response == null) {
          this.setStatus(
            "⚠ Offline — changes to this shared vault aren't saved yet; keep this page open until you're back online and make another change",
          );
          return;
        }
        if (response.status === 412) {
          if (!(await this.mergeLatest())) return;
          continue;
        }
        if (!response.ok) {
          this.setStatus(await failure(response, "save"));
          return;
        }
        this.etag = response.headers.get("ETag");
        this.base = JSON.parse(json) as VaultRoot;
        this.info = { ...this.info, size: blob.byteLength };
        this.showUsage();
        return;
      }
      this.setStatus("⚠ Save failed: the vault keeps changing");
    }

    /** Merges in the changes someone else saved first. Where the same item
     *  was changed on both sides their version is kept, and listed. */
    private async mergeLatest(): Promise<boolean> {
      if (this.data == null || this.base == null) return false;
      this.setStatus("Merging changes made by someone else…");
      const latest = await this.download();
      if (typeof latest === "string") {
        this.setStatus(latest);
        return false;
      }
      const { merged, conflicts } = mergeVaults(
        this.base,
        this.data,
        latest.data,
      );
      this.base = latest.data;
      this.data = merged;
      this.etag = latest.etag;
      this.render();
      if (conflicts.length > 0) {
        const notice = el("div", "pm-conflict");
        notice.setAttribute("role", "alert");
        const p = el(
          "p",
          "",
          "Someone else changed some of the same items at the same time; their version was kept for:",
        );
        const ul = document.createElement("ul");
        for (const c of conflicts.slice(0, 10)) ul.append(el("li", "", c));
        const dismiss = button("OK");
        dismiss.addEventListener("click", () => notice.remove());
        notice.append(p, ul, dismiss);
        this.tablesDiv.prepend(notice);
      }
      return true;
    }

    // ── Rendering ───────────────────────────────────────────────────────────

    private render(): void {
      const data = this.data;
      if (data == null) return;
      this.tablesDiv.replaceChildren();
      const callbacks: PassTableCallbacks = {
        onFetchBeforeEdit: () => Promise.resolve(),
        onAction: (entry) => this.record(entry),
      };
      const renderTable = (table: PassTableData, before: Node | null) => {
        const div = document.createElement("div");
        renderPassTable(table, div, callbacks, () => {
          const idx = data.tables.indexOf(table);
          if (idx < 0) return;
          const tableSnapshot = structuredClone(table);
          div.remove();
          data.tables.splice(idx, 1);
          void callbacks.onAction({
            kind: "table-delete",
            timestamp: new Date().toISOString(),
            tableId: table.id,
            tableIndex: idx,
            tableSnapshot,
          });
        });
        this.tablesDiv.insertBefore(div, before);
      };
      data.tables.forEach((table) => renderTable(table, null));
      const addButton = el("button", "pm-add-btn");
      addButton.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4.5v15m7.5-7.5h-15"/></svg>Add Table`;
      addButton.type = "button";
      addButton.addEventListener("click", () => {
        const table: PassTableData = {
          id: crypto.randomUUID(),
          rowIds: [],
          name: "New Table",
          columns: [],
        };
        data.tables.push(table);
        renderTable(table, addButton);
        void callbacks.onAction({
          kind: "table-add",
          timestamp: new Date().toISOString(),
          tableId: table.id,
          tableName: table.name,
        });
      });
      this.tablesDiv.append(addButton);
    }

    /** Members, and (for owners) adding members, renaming and deleting. */
    private renderManage(): void {
      const session = getSession();
      if (session == null) return;
      const me = session.username;
      const { info } = this;
      const isOwner = info.role === "Owner";
      const owners = info.members.filter((m) => m.role === "Owner").length;
      const manageStatus = el("p", "pm-chg-pass-status");
      const run = async (
        action: string,
        task: () => Promise<Response | null>,
      ): Promise<boolean> => {
        manageStatus.textContent = "…";
        const response = await task();
        if (response == null || !response.ok) {
          manageStatus.textContent = await failure(response, action);
          return false;
        }
        manageStatus.textContent = "";
        await refresh();
        return true;
      };
      const memberPath = (username: string) =>
        `/shared-vaults/${info.id}/members/${encodeURIComponent(username)}`;

      this.manageDiv.replaceChildren();
      this.manageDiv.append(el("p", "pm-device-status", "Members"));
      const members = el("ul", "pm-member-list");
      for (const member of info.members) {
        const li = document.createElement("li");
        li.dataset.username = member.username;
        li.append(
          el(
            "span",
            "pm-member-name",
            member.username === me
              ? `${member.username} (you)`
              : member.username,
          ),
        );
        const lastOwner = member.role === "Owner" && owners === 1;
        if (isOwner && info.writable && !lastOwner) {
          const roleSelect = document.createElement("select");
          roleSelect.setAttribute("aria-label", `Role of ${member.username}`);
          for (const role of ["Owner", "Editor"] as const)
            roleSelect.add(new Option(role, role, false, role === member.role));
          roleSelect.addEventListener("change", () =>
            run("change the role", () =>
              request("PUT", memberPath(member.username), {
                json: { role: roleSelect.value },
              }),
            ),
          );
          li.append(roleSelect);
        } else li.append(el("span", "pm-shared-meta", member.role));
        const canRemove = (isOwner || member.username === me) && !lastOwner;
        if (canRemove) {
          const remove = button(member.username === me ? "Leave" : "Remove");
          remove.addEventListener("click", () => {
            const question =
              member.username === me
                ? `Leave "${this.name}"? You'll need to be added again to open it.`
                : `Remove ${member.username} from "${this.name}"? They have already seen its contents, so change any passwords they shouldn't keep using.`;
            if (!window.confirm(question)) return;
            void run("remove the member", () =>
              request("DELETE", memberPath(member.username)),
            );
          });
          li.append(remove);
        }
        members.append(li);
      }
      this.manageDiv.append(members);

      if (isOwner && info.writable && this.key != null)
        this.manageDiv.append(this.addMemberForm(run, memberPath));

      if (isOwner) {
        const actions = el("div", "pm-device-actions");
        if (info.writable && this.key != null) {
          const rename = button("Rename");
          rename.addEventListener("click", () => {
            const name = window.prompt("New name", this.name)?.trim();
            if (!name || name === this.name || this.key == null) return;
            const encryptedName = toBase64Url(
              encryptBlob(this.key, encoder.encode(name)),
            );
            void run("rename the vault", () =>
              request("PATCH", `/shared-vaults/${info.id}`, {
                json: { encryptedName },
              }),
            );
          });
          actions.append(rename);
        }
        const del = button(
          "Delete shared vault",
          "pm-btn pm-btn-ghost pm-danger-text",
        );
        del.addEventListener("click", () => {
          if (
            !window.confirm(
              `Delete "${this.name}" and all its tables for everyone in it? This can't be undone.`,
            )
          )
            return;
          void run("delete the vault", () =>
            request("DELETE", `/shared-vaults/${info.id}`),
          );
        });
        actions.append(del);
        this.manageDiv.append(actions);
      }
      this.manageDiv.append(manageStatus);
    }

    private addMemberForm(
      run: (
        action: string,
        task: () => Promise<Response | null>,
      ) => Promise<boolean>,
      memberPath: (username: string) => string,
    ): HTMLFormElement {
      const form = el("form", "pm-inline-form pm-add-member");
      const username = document.createElement("input");
      username.name = "member-username";
      username.placeholder = "Username to add";
      username.autocomplete = "off";
      username.setAttribute("aria-label", "Username to add");
      const role = document.createElement("select");
      role.name = "member-role";
      role.setAttribute("aria-label", "Role");
      role.add(new Option("Editor", "Editor", true, true));
      role.add(new Option("Owner", "Owner"));
      const lookup = el("button", "pm-btn pm-btn-primary", "Add member");
      lookup.type = "submit";
      const confirmDiv = el("div", "pm-add-member-confirm");
      confirmDiv.hidden = true;
      form.append(username, role, lookup, confirmDiv);

      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const name = username.value.trim();
        if (!name || this.key == null) return;
        if (this.info.members.length >= this.info.maxMembers) {
          confirmDiv.hidden = false;
          confirmDiv.textContent = `This vault already has the maximum of ${this.info.maxMembers} members.`;
          return;
        }
        lookup.disabled = true;
        try {
          const response = await request("GET", "/sharing-key", {
            query: { user: name },
          });
          confirmDiv.hidden = false;
          confirmDiv.replaceChildren();
          if (response?.status === 404) {
            confirmDiv.textContent = `No user named ${name} has set up sharing. They need to log in and choose "Set up sharing" first.`;
            return;
          }
          if (response == null || !response.ok) {
            confirmDiv.textContent = await failure(
              response,
              "look up the user",
            );
            return;
          }
          const { publicKey } = (await response.json()) as {
            publicKey: string;
          };
          const check = el(
            "p",
            "pm-field-hint",
            `${name}'s sharing key fingerprint is ${await fingerprint(publicKey)}. To be sure the vault is shared with them and no one else, check it matches the one they see under Shared Vaults.`,
          );
          const confirmButton = button(
            `Add ${name} as ${role.value}`,
            "pm-btn pm-btn-primary",
          );
          const cancel = button("Cancel");
          cancel.addEventListener("click", () => {
            confirmDiv.hidden = true;
            confirmDiv.replaceChildren();
          });
          confirmButton.addEventListener("click", async () => {
            if (this.key == null) return;
            confirmButton.disabled = true;
            const wrappedKey = toBase64Url(
              sealTo(fromBase64Url(publicKey), this.key),
            );
            const added = await run("add the member", () =>
              request("PUT", memberPath(name), {
                json: { role: role.value, wrappedKey, publicKey },
              }),
            );
            confirmButton.disabled = false;
            if (added) username.value = "";
          });
          confirmDiv.append(check, confirmButton, cancel);
        } finally {
          lookup.disabled = false;
        }
      });
      return form;
    }
  }

  return {
    show(): void {
      void (async () => {
        await renderSetup();
        if (getSharingKeys() == null) {
          renderEmpty();
          return;
        }
        // publishes the key again in case that didn't finish before
        const keys = await ensureSharingKeys();
        if (typeof keys === "string") status.textContent = keys;
        await refresh();
      })();
    },

    clear(): void {
      generation++;
      cards.clear();
      list.replaceChildren();
      status.textContent = "";
      intro.textContent = "";
      fingerprintLine.textContent = "";
      createName.value = "";
    },

    hasUnsavedChanges(): boolean {
      for (const card of cards.values())
        if (card.hasUnsavedChanges()) return true;
      return false;
    },
  };
}
