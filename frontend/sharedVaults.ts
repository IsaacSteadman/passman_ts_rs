// The Shared Vaults section: the user's sharing identity, the people they've
// verified, and the shared vaults they're in (see sharedVaultModel.ts for how
// those are checked, saved and kept on the device).

import type { Session } from "./contentArea";
import { listSharedVaults } from "./deviceStore";
import {
  type HistoryEntry,
  type PassTableCallbacks,
  type PassTableData,
  type SharingContact,
  type SharingData,
  describeHistoryEntry,
  renderPassTable,
} from "./PassTable";
import {
  OfflineError,
  ServerError,
  SharedVault,
  SharingClient,
} from "./sharedVaultModel";
import {
  type Member,
  fingerprintOf,
  formatFingerprint,
  identityBundle,
  newIdentitySecret,
} from "./sharingCrypto";
import {
  closeVerificationDialogs,
  showMyCode,
  verifyUser,
} from "./verification";

export interface SharedVaultsPanelHandle {
  /** Loads the shared vaults (after unlocking). */
  show(): void;
  /** Forgets the keys and decrypted vaults (on locking). */
  clear(): void;
  /** Whether a change to a shared vault would be lost by locking now. */
  hasUnsavedChanges(): boolean;
}

export interface SharedVaultsDeps {
  getSession: () => Session | null;
  getSharing: () => SharingData | null;
  /** Saves the sharing identity and contacts in the user's own vault; true
   *  once the server has them. */
  setSharing: (sharing: SharingData) => Promise<boolean>;
  /** The account's id on this device if it's remembered. */
  cacheAccount: () => string | null;
  /** Adds tables to the user's own vault. */
  copyToOwnVault: (tables: PassTableData[]) => Promise<void>;
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

function button(
  label: string,
  className = "pm-btn pm-btn-ghost",
): HTMLButtonElement {
  const b = el("button", className, label);
  b.type = "button";
  return b;
}

function checkbox(label: string, checked: boolean): HTMLLabelElement {
  const wrap = el("label", "pm-member-perm");
  const input = el("input");
  input.type = "checkbox";
  input.checked = checked;
  wrap.append(input, document.createTextNode(label));
  return wrap;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function errorMessage(e: unknown): string {
  if (e instanceof OfflineError) return "can't reach the server";
  return e instanceof Error ? e.message : String(e);
}

const plusIcon = `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4.5v15m7.5-7.5h-15"/></svg>`;

export function initSharedVaultsPanel(
  deps: SharedVaultsDeps,
): SharedVaultsPanelHandle {
  const panel = document.querySelector("#shared-vaults") as HTMLElement;
  const field = <T extends Element>(selector: string) =>
    panel.querySelector(selector) as T;
  const intro = field<HTMLElement>("[name='shared-intro']");
  const setupButton = field<HTMLButtonElement>("button[name='setup-sharing']");
  const identityDiv = field<HTMLElement>("[name='sharing-identity']");
  const fingerprintLine = field<HTMLElement>("[name='sharing-fingerprint']");
  const showCodeButton = field<HTMLButtonElement>(
    "button[name='show-my-code']",
  );
  const verifyForm = field<HTMLFormElement>("form[name='verify-someone']");
  const verifyName = field<HTMLInputElement>("input[name='verify-username']");
  const contactsDetails = field<HTMLDetailsElement>("details[name='contacts']");
  const list = field<HTMLElement>("[name='shared-list']");
  const createForm = field<HTMLFormElement>("form[name='create-shared']");
  const createName = field<HTMLInputElement>("input[name='shared-name']");
  const status = field<HTMLElement>("[name='shared-status']");

  const client = new SharingClient({
    session: deps.getSession,
    sharing: deps.getSharing,
    cacheAccount: deps.cacheAccount,
  });
  const cards = new Map<string, VaultCard>();
  /** The user's own fingerprint, by identity secret. */
  let ownFingerprint: { secret: string; fingerprint: string } | null = null;

  function myFingerprint(): string | null {
    const sharing = deps.getSharing();
    if (sharing == null) return null;
    if (ownFingerprint?.secret !== sharing.identitySecret)
      ownFingerprint = {
        secret: sharing.identitySecret,
        fingerprint: fingerprintOf(identityBundle(sharing.identitySecret)),
      };
    return ownFingerprint.fingerprint;
  }

  function contacts(): Record<string, SharingContact> {
    return deps.getSharing()?.contacts ?? {};
  }

  // ── Identity ──────────────────────────────────────────────────────────────

  /** Creates the user's identity if needed and makes sure the server has
   *  it. Returns an error to show, or null. */
  async function ensureIdentity(): Promise<string | null> {
    let sharing = deps.getSharing();
    if (sharing == null) {
      const session = deps.getSession();
      if (session == null) return "Not logged in";
      if ((await client.identityOf(session.username)) != null)
        return "Sharing was set up in another session. Reload the page to use it here.";
      sharing = { identitySecret: newIdentitySecret(), contacts: {} };
      // kept in the vault before it's published, so the identity can't be
      // lost while others give it access to their vaults
      if (!(await deps.setSharing(sharing)))
        return "⚠ Couldn't save your sharing identity to your vault (see the status at the top). Try again once it's saved.";
    }
    try {
      await client.publishIdentity(sharing.identitySecret);
    } catch (e) {
      if (e instanceof ServerError && e.type === "E_IDENTITY_IN_USE")
        return "⚠ The server has a different sharing identity for you, which shared vaults use. Your vault's identity can't replace it.";
      throw e;
    }
    return null;
  }

  function renderIdentity(): void {
    const fingerprint = myFingerprint();
    setupButton.hidden = fingerprint != null;
    identityDiv.hidden = fingerprint == null;
    createForm.hidden = fingerprint == null;
    intro.textContent =
      fingerprint == null
        ? "Share tables with people you trust. Setting up sharing creates your sharing identity: post-quantum keys kept in your vault, whose public half others use to give you access."
        : "Vaults you share with other people. Only members can read them, and before adding someone you verify their identity in person or on a call.";
    fingerprintLine.textContent =
      fingerprint == null
        ? ""
        : `Your identity's fingerprint: ${formatFingerprint(fingerprint)}`;
    renderContacts();
  }

  function renderContacts(): void {
    const entries = Object.entries(contacts()).sort(([a], [b]) =>
      a.localeCompare(b),
    );
    const summary = el(
      "summary",
      "",
      `People you've verified (${entries.length})`,
    );
    const ul = el("ul", "pm-member-list");
    for (const [name, contact] of entries) {
      const li = el("li");
      li.dataset.username = name;
      li.append(
        el("span", "pm-member-name", name),
        el(
          "span",
          "pm-shared-meta",
          `${contact.method === "qr" ? "QR code" : "safety number"}, ${new Date(contact.verifiedAt).toLocaleDateString()}`,
        ),
      );
      const forget = button("Forget");
      forget.addEventListener("click", async () => {
        const sharing = deps.getSharing();
        if (sharing == null) return;
        const rest = { ...sharing.contacts };
        delete rest[name];
        await deps.setSharing({ ...sharing, contacts: rest });
        renderContacts();
        for (const card of cards.values()) card.render();
      });
      li.append(forget);
      ul.append(li);
    }
    if (entries.length === 0)
      ul.append(
        el(
          "li",
          "pm-empty-note",
          "Nobody yet. Verify someone to be able to add them to a vault.",
        ),
      );
    contactsDetails.replaceChildren(summary, ul);
  }

  setupButton.addEventListener("click", async () => {
    setupButton.disabled = true;
    status.textContent = "Setting up sharing…";
    try {
      status.textContent = (await ensureIdentity()) ?? "";
      renderIdentity();
      if (deps.getSharing()) await refresh();
    } catch (e) {
      status.textContent = `⚠ Couldn't set up sharing: ${errorMessage(e)}`;
    } finally {
      setupButton.disabled = false;
    }
  });

  showCodeButton.addEventListener("click", () => {
    const session = deps.getSession();
    const fingerprint = myFingerprint();
    if (session && fingerprint) showMyCode(session.username, fingerprint);
  });

  verifyForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const name = verifyName.value.trim();
    const session = deps.getSession();
    const fingerprint = myFingerprint();
    if (!name || session == null || fingerprint == null) return;
    if (name === session.username) {
      status.textContent = "That's you.";
      return;
    }
    status.textContent = "Looking them up…";
    let identity: Awaited<ReturnType<SharingClient["identityOf"]>>;
    try {
      identity = await client.identityOf(name);
    } catch (e) {
      status.textContent = `⚠ Couldn't look up ${name}: ${errorMessage(e)}`;
      return;
    }
    if (identity == null) {
      status.textContent = `No user named ${name} has set up sharing.`;
      return;
    }
    status.textContent = "";
    verifyName.value = "";
    verifyUser({
      me: { username: session.username, fingerprint },
      target: { username: name, fingerprint: identity.fingerprint },
      onVerified: async (contact) => {
        const sharing = deps.getSharing();
        if (sharing == null) return;
        await deps.setSharing({
          ...sharing,
          contacts: { ...sharing.contacts, [name]: contact },
        });
        renderContacts();
        for (const card of cards.values()) card.render();
      },
    });
  });

  // ── Vaults ────────────────────────────────────────────────────────────────

  function addCard(vault: SharedVault, open = false): VaultCard {
    const card = new VaultCard(vault);
    cards.set(vault.id, card);
    list.append(card.details);
    card.details.open = open;
    renderEmpty();
    return card;
  }

  function removeCard(id: string): void {
    cards.get(id)?.details.remove();
    cards.delete(id);
    renderEmpty();
  }

  function renderEmpty(): void {
    list.querySelector(":scope > .pm-empty-note")?.remove();
    if (cards.size === 0 && deps.getSharing())
      list.append(
        el(
          "p",
          "pm-empty-note",
          "No shared vaults yet. Create one, or ask someone to verify you and add you to theirs.",
        ),
      );
  }

  /** Shows the vaults kept on this device, before reaching the server. */
  async function loadCached(): Promise<void> {
    const account = deps.cacheAccount();
    if (account == null) return;
    for (const cached of await listSharedVaults(account).catch(() => [])) {
      if (cards.has(cached.vaultId)) continue;
      try {
        addCard(SharedVault.fromCache(client, cached));
      } catch (e) {
        status.textContent = `⚠ Couldn't open a shared vault kept on this device: ${errorMessage(e)}`;
      }
    }
  }

  let refreshing: Promise<void> | null = null;

  /** Brings every vault up to date with the server. */
  function refresh(): Promise<void> {
    refreshing ??= (async () => {
      try {
        const infos = await client.listVaults();
        const listed = new Set(infos.map((info) => info.id));
        for (const info of infos) {
          const card = cards.get(info.id);
          if (card) void card.vault.sync(info);
          else {
            try {
              const vault = await SharedVault.download(client, info);
              addCard(vault);
              // e.g. to remove members who left
              void vault.sync(info);
            } catch (e) {
              status.textContent = `⚠ Couldn't open a shared vault: ${errorMessage(e)}`;
            }
          }
        }
        for (const [id, card] of cards)
          if (!listed.has(id)) card.vault.markRemoved();
        if (status.textContent?.startsWith("Offline")) status.textContent = "";
      } catch (e) {
        status.textContent =
          e instanceof OfflineError
            ? "Offline — shared vaults kept on this device can still be opened"
            : `⚠ Couldn't load shared vaults: ${errorMessage(e)}`;
      } finally {
        refreshing = null;
        renderEmpty();
      }
    })();
    return refreshing;
  }

  window.addEventListener("online", () => {
    if (deps.getSharing() && deps.getSession()) void refresh();
  });

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
      const problem = await ensureIdentity();
      if (problem) {
        status.textContent = problem;
        return;
      }
      const vault = await SharedVault.create(client, name);
      createName.value = "";
      status.textContent = "";
      addCard(vault, true);
      await refresh();
    } catch (e) {
      status.textContent = `⚠ Couldn't create the shared vault: ${errorMessage(e)}`;
    } finally {
      submit.disabled = false;
    }
  });

  // ── One vault ─────────────────────────────────────────────────────────────

  class VaultCard {
    readonly details = el("details", "pm-chg-pass-details pm-shared-vault");
    private readonly summaryName = el("span", "pm-shared-name");
    private readonly summaryMeta = el("span", "pm-shared-meta");
    private readonly statusLine = el("p", "pm-chg-pass-status");
    private readonly noticeDiv = el("div");
    private readonly tablesDiv = el("div", "pm-shared-tables");
    private readonly historyDetails = el("details", "pm-history-details");
    private readonly membersDiv = el("div", "pm-device-subsection");
    private readonly actionsDiv = el("div", "pm-device-actions");
    /** What the tables were last drawn from, so they're only redrawn (which
     *  would end an edit in progress) when that changes. */
    private drawn: { data: object; readOnly: boolean } | null = null;
    /** Member list changes not applied yet. */
    private draft: Member[] | null = null;

    constructor(readonly vault: SharedVault) {
      const summary = el("summary");
      summary.append(this.summaryName, this.summaryMeta);
      const body = el("div", "pm-chg-pass-body");
      this.historyDetails.append(el("summary", "", "History"));
      this.historyDetails.addEventListener("toggle", () => {
        if (this.historyDetails.open) void this.showHistory();
      });
      body.append(
        this.statusLine,
        this.noticeDiv,
        this.tablesDiv,
        this.historyDetails,
        this.membersDiv,
        this.actionsDiv,
      );
      this.details.append(summary, body);
      vault.onChange = () => this.render();
      this.render();
    }

    render(): void {
      const { vault } = this;
      if (vault.removed && vault.stranded == null) {
        removeCard(vault.id);
        return;
      }
      const me = vault.me;
      const members = vault.latest.body.members;
      this.summaryName.textContent = vault.data.name;
      const parts = [
        vault.removed
          ? "No longer a member"
          : vault.canWrite()
            ? "Can edit"
            : "Read only",
      ];
      if (me?.manage && !vault.removed) parts.push("Manages members");
      parts.push(
        `${members.length} ${members.length === 1 ? "member" : "members"}`,
      );
      if (vault.hasUnsavedChanges()) parts.push("unsaved changes");
      this.summaryMeta.textContent = parts.join(" · ");

      const { info } = vault;
      const usage =
        info == null
          ? ""
          : info.maxDataSize == null
            ? `Uses ${formatSize(info.size)}.`
            : `Uses ${formatSize(info.size)} of ${formatSize(info.maxDataSize)}.`;
      const readOnlyNote =
        info?.writable === false
          ? " The server no longer allows changes to this vault."
          : "";
      const status =
        vault.status && !/[.…]$/.test(vault.status)
          ? `${vault.status}.`
          : vault.status;
      this.statusLine.textContent =
        [status, usage].filter(Boolean).join(" ") + readOnlyNote;

      this.renderNotices();
      const readOnly = !vault.canWrite() || vault.removed;
      if (this.drawn?.data !== vault.data || this.drawn.readOnly !== readOnly) {
        this.renderTables(readOnly);
        this.drawn = { data: vault.data, readOnly };
      }
      this.renderMembers();
      this.renderActions();
    }

    private renderNotices(): void {
      const { vault } = this;
      if (vault.conflicts.length > 0) {
        const notice = el("div", "pm-conflict");
        notice.setAttribute("role", "alert");
        const ul = el("ul");
        for (const c of vault.conflicts.splice(0).slice(0, 10))
          ul.append(el("li", "", c));
        const ok = button("OK");
        ok.addEventListener("click", () => notice.remove());
        notice.append(
          el(
            "p",
            "",
            "Someone else changed some of the same items at the same time; their version was kept for:",
          ),
          ul,
          ok,
        );
        this.noticeDiv.append(notice);
      }
      // anyone with a user's public identity can add them to a vault (even
      // the server, with an identity of its own), so say when a vault is run
      // by someone this user hasn't verified
      this.noticeDiv.querySelector(".pm-unverified-managers")?.remove();
      const unverified = vault.latest.body.members.filter(
        (m) => m.manage && !this.verification(m).ok,
      );
      if (unverified.length > 0) {
        const names = unverified.map((m) => m.username).join(", ");
        this.noticeDiv.append(
          el(
            "p",
            "pm-conflict pm-unverified-managers",
            `⚠ This vault is managed by ${names}, whose identity you haven't verified. Verify them before trusting it with new passwords: otherwise it could be someone else (even the server) posing as them.`,
          ),
        );
      }
      this.noticeDiv.querySelector(".pm-stranded")?.remove();
      if (vault.stranded) {
        const box = el("div", "pm-conflict pm-stranded");
        box.setAttribute("role", "alert");
        const copy = button("Copy them to my vault", "pm-btn pm-btn-primary");
        copy.addEventListener("click", async () => {
          if (vault.stranded == null) return;
          await deps.copyToOwnVault(vault.stranded.tables);
          vault.discardStranded();
        });
        const discard = button("Discard them");
        discard.addEventListener("click", () => {
          if (
            window.confirm(
              "Discard the changes that couldn't be saved to this shared vault?",
            )
          )
            vault.discardStranded();
        });
        box.append(
          el(
            "p",
            "",
            vault.removed
              ? "You're no longer a member of this vault, so your unsaved changes to it can't be saved. You can keep a copy of its tables (with your changes) in your own vault."
              : "You can no longer change this vault, so your unsaved changes to it can't be saved. You can keep a copy of its tables (with your changes) in your own vault.",
          ),
          copy,
          discard,
        );
        this.noticeDiv.append(box);
      }
    }

    private renderTables(readOnly: boolean): void {
      const { vault } = this;
      const data = vault.data;
      this.tablesDiv.replaceChildren();
      const callbacks: PassTableCallbacks = {
        onFetchBeforeEdit: () => Promise.resolve(),
        onAction: (entry) => vault.record(entry),
        readOnly,
      };
      const renderTable = (table: PassTableData, before: Node | null) => {
        const div = el("div");
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
      if (data.tables.length === 0 && readOnly)
        this.tablesDiv.append(el("p", "pm-empty-note", "No tables yet."));
      if (readOnly) return;
      const addButton = el("button", "pm-add-btn");
      addButton.type = "button";
      addButton.innerHTML = `${plusIcon}Add Table`;
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

    private async showHistory(): Promise<void> {
      const listDiv = el("div", "pm-history-list");
      this.historyDetails.replaceChildren(
        el("summary", "", "History"),
        listDiv,
      );
      listDiv.append(el("p", "pm-empty-note", "Loading…"));
      let entries: HistoryEntry[];
      try {
        entries = await this.vault.fullHistory();
      } catch (e) {
        listDiv.replaceChildren(
          el(
            "p",
            "pm-empty-note",
            `Couldn't load the history: ${errorMessage(e)}`,
          ),
        );
        return;
      }
      listDiv.replaceChildren();
      if (entries.length === 0)
        listDiv.append(el("p", "pm-empty-note", "No history yet."));
      for (const entry of [...entries].reverse()) {
        const row = el("div", "pm-history-entry");
        row.append(
          el(
            "span",
            "pm-history-desc",
            `${new Date(entry.timestamp).toLocaleString()} — ${describeHistoryEntry(entry)}`,
          ),
        );
        listDiv.append(row);
      }
      listDiv.append(
        el(
          "p",
          "pm-field-hint",
          "Shows changes made while you've been a member.",
        ),
      );
    }

    /** How this user knows a member's identity. */
    private verification(member: Member): { text: string; ok: boolean } {
      const session = deps.getSession();
      if (member.username === session?.username)
        return { text: "you", ok: true };
      const contact = contacts()[member.username];
      if (contact == null) return { text: "not verified by you", ok: false };
      if (contact.fingerprint !== member.fingerprint)
        return { text: "⚠ not the identity you verified", ok: false };
      return { text: "✓ verified by you", ok: true };
    }

    private renderMembers(): void {
      const { vault } = this;
      const canManage = vault.canManage() && !vault.removed;
      const current = vault.latest.body.members;
      const members = this.draft ?? current;
      const leaving = new Set(vault.info?.leaving ?? []);
      const session = deps.getSession();
      this.membersDiv.replaceChildren(el("p", "pm-device-status", "Members"));
      const ul = el("ul", "pm-member-list");
      for (const member of members) {
        const li = el("li");
        li.dataset.username = member.username;
        const { text, ok } = this.verification(member);
        const nameSpan = el("span", "pm-member-name", member.username);
        const badge = el(
          "span",
          ok ? "pm-shared-meta" : "pm-shared-meta pm-unverified",
          text,
        );
        li.append(nameSpan, badge);
        if (leaving.has(member.username))
          li.append(el("span", "pm-shared-meta", "leaving"));
        if (!current.some((m) => m.username === member.username))
          li.append(el("span", "pm-shared-meta pm-member-new", "to be added"));
        if (canManage) {
          const write = checkbox("can edit", member.write);
          const manage = checkbox("manages members", member.manage);
          const update = () =>
            this.updateDraft(member.username, {
              write: write.querySelector("input")!.checked,
              manage: manage.querySelector("input")!.checked,
            });
          write.querySelector("input")!.addEventListener("change", update);
          manage.querySelector("input")!.addEventListener("change", update);
          li.append(write, manage);
          if (member.username !== session?.username) {
            const remove = button("Remove");
            remove.addEventListener("click", () =>
              this.setDraft(members.filter((m) => m !== member)),
            );
            li.append(remove);
          }
        } else
          li.append(
            el(
              "span",
              "pm-shared-meta",
              [
                member.write ? "can edit" : "read only",
                member.manage ? "manages members" : "",
              ]
                .filter(Boolean)
                .join(", "),
            ),
          );
        ul.append(li);
      }
      this.membersDiv.append(ul);
      if (!canManage) return;

      // adding: only people this user has verified
      const candidates = Object.entries(contacts()).filter(
        ([name]) => !members.some((m) => m.username === name),
      );
      const addForm = el("form", "pm-inline-form pm-add-member");
      if (candidates.length === 0)
        addForm.append(
          el(
            "p",
            "pm-field-hint",
            Object.keys(contacts()).length === 0
              ? "To add someone, verify them first (under Shared Vaults above)."
              : "Everyone you've verified is a member. To add someone else, verify them first (under Shared Vaults above).",
          ),
        );
      else {
        const select = el("select");
        select.name = "add-member";
        select.setAttribute("aria-label", "Person to add");
        for (const [name] of candidates) select.add(new Option(name, name));
        const write = checkbox("can edit", true);
        const manage = checkbox("manages members", false);
        const add = el("button", "pm-btn pm-btn-ghost", "Add");
        add.type = "submit";
        addForm.append(select, write, manage, add);
        addForm.addEventListener("submit", (event) => {
          event.preventDefault();
          const contact = contacts()[select.value];
          if (contact == null) return;
          this.setDraft([
            ...members,
            {
              username: select.value,
              fingerprint: contact.fingerprint,
              write: write.querySelector("input")!.checked,
              manage: manage.querySelector("input")!.checked,
            },
          ]);
        });
      }
      this.membersDiv.append(addForm);

      if (this.draft != null) {
        const apply = button("Apply member changes", "pm-btn pm-btn-primary");
        apply.name = "apply-members";
        const cancel = button("Cancel");
        cancel.addEventListener("click", () => this.setDraft(null));
        apply.addEventListener("click", () => this.applyDraft());
        const row = el("div", "pm-device-actions");
        row.append(apply, cancel);
        this.membersDiv.append(
          el(
            "p",
            "pm-field-hint",
            "Applying gives the vault a new key that only these members get, so anyone removed can't read anything saved afterwards (and anyone added can't read what was saved before).",
          ),
          row,
        );
      }
    }

    private setDraft(members: Member[] | null): void {
      const current = this.vault.latest.body.members;
      this.draft =
        members != null && JSON.stringify(members) !== JSON.stringify(current)
          ? members
          : null;
      this.renderMembers();
    }

    private updateDraft(
      username: string,
      perms: Pick<Member, "write" | "manage">,
    ): void {
      const members = this.draft ?? this.vault.latest.body.members;
      this.setDraft(
        members.map((m) => (m.username === username ? { ...m, ...perms } : m)),
      );
    }

    private async applyDraft(): Promise<void> {
      const draft = this.draft;
      if (draft == null) return;
      if (!draft.some((m) => m.manage)) {
        this.vault.status = "⚠ Someone must still manage members.";
        this.render();
        return;
      }
      this.draft = null;
      await this.vault.changeMembers(draft);
    }

    private renderActions(): void {
      const { vault } = this;
      this.actionsDiv.replaceChildren();
      if (vault.removed) return;
      const leave = button("Leave");
      leave.addEventListener("click", async () => {
        if (
          !window.confirm(
            `Leave "${vault.data.name}"? You'll need to be added again to open it.`,
          )
        )
          return;
        try {
          await vault.leave();
          removeCard(vault.id);
        } catch (e) {
          vault.status = `⚠ Couldn't leave: ${errorMessage(e)}`;
          this.render();
        }
      });
      this.actionsDiv.append(leave);
      if (vault.canManage()) {
        const del = button(
          "Delete shared vault",
          "pm-btn pm-btn-ghost pm-danger-text",
        );
        del.addEventListener("click", async () => {
          if (
            !window.confirm(
              `Delete "${vault.data.name}" and all its tables for everyone in it? This can't be undone.`,
            )
          )
            return;
          try {
            await vault.deleteVault();
            removeCard(vault.id);
          } catch (e) {
            vault.status = `⚠ Couldn't delete: ${errorMessage(e)}`;
            this.render();
          }
        });
        this.actionsDiv.append(del);
      }
    }
  }

  return {
    show(): void {
      renderIdentity();
      if (deps.getSharing() == null) {
        renderEmpty();
        return;
      }
      void (async () => {
        await loadCached();
        renderEmpty();
        try {
          const problem = await ensureIdentity();
          if (problem) status.textContent = problem;
        } catch (e) {
          if (!(e instanceof OfflineError))
            status.textContent = `⚠ ${errorMessage(e)}`;
        }
        await refresh();
      })();
    },

    clear(): void {
      client.reset();
      cards.clear();
      ownFingerprint = null;
      list.replaceChildren();
      contactsDetails.replaceChildren();
      status.textContent = "";
      intro.textContent = "";
      fingerprintLine.textContent = "";
      createName.value = "";
      verifyName.value = "";
      closeVerificationDialogs();
    },

    hasUnsavedChanges(): boolean {
      // a remembered account's changes are kept on the device
      if (deps.cacheAccount() != null) return false;
      for (const card of cards.values())
        if (card.vault.hasUnsavedChanges()) return true;
      return false;
    },
  };
}
