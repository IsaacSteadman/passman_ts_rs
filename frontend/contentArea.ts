import {
  accountId,
  forgetAccount,
  putAccount,
  putVault,
  requestPersistentStorage,
} from "./deviceStore";
import { keyProtector, unlockErrorMessage } from "./keyProtector";
import type { LoginResult, SyncedVault } from "./loginArea";
import {
  credentialHeaders,
  decodeVault,
  deriveUserKeys,
  describeError,
  downloadVault,
} from "./loginArea";
import { mergeVaults, vaultsEqual } from "./merge";
import {
  type VaultRoot,
  type PassTableData,
  type HistoryEntry,
  type PassTableCallbacks,
  type CellValue,
  type LinkCellData,
  type PasswordCellData,
  getDefaultCellValue,
  setCellValue,
  spliceCellValue,
  renderPassTable,
} from "./PassTable";
import { encryptBlob } from "./passman_crypto_glue";

export interface ContentAreaHandle {
  show(result: LoginResult): void;
  getCurrentData(): VaultRoot | null;
  /** Records changes made to the data outside the tables (history), shows
   *  them and saves. */
  recordChanges(entries: HistoryEntry[]): Promise<void>;
}

export function initContentArea(
  contentDiv: HTMLDivElement,
  onLogout: () => void,
): ContentAreaHandle {
  const dataDiv = contentDiv.querySelector(
    "div[name='data']",
  ) as HTMLDivElement;
  const statSpan = contentDiv.querySelector(
    "span[name='stat-span']",
  ) as HTMLSpanElement;
  const saveButton = contentDiv.querySelector(
    "button[name='save']",
  ) as HTMLButtonElement;
  const historyButton = contentDiv.querySelector(
    "button[name='history']",
  ) as HTMLButtonElement;
  const logoutButton = contentDiv.querySelector(
    "button[name='logout']",
  ) as HTMLButtonElement;

  let currentEncryptionKey: Uint8Array | null = null;
  let currentUsername: string | null = null;
  let currentAuthKeyB64: string | null = null;
  let currentServerPass: string | null = null;
  let currentServerNs: string | null = null;
  let currentLastModified: string | null = null;
  let currentData: VaultRoot | null = null;
  // The server version this session last loaded or saved: its ETag (sent as
  // If-Match so a save never overwrites a newer one) and its contents (the
  // base for merging when another session saved first).
  let currentEtag: string | null = null;
  let baseData: VaultRoot | null = null;
  // `baseData` encrypted, exactly as the server holds it
  let baseBlob: Uint8Array | null = null;
  // Set when a merge found changes made in both sessions; saving is paused
  // until the user loads the latest version.
  let conflict: SyncedVault | null = null;
  // Set when the server rejected the auth key because the password was changed
  // in another session; saving is paused until the new one is entered.
  let passwordChanged = false;
  // Whether the account is remembered on this device: its last server version
  // and unsaved changes are then kept in IndexedDB (encrypted), so it can be
  // unlocked and edited offline.
  let remembered = false;
  // Whether this session has reached the server since it was unlocked.
  let reachedServer = false;
  // Throttle: only fetch from server if this many ms have elapsed since last fetch.
  const FETCH_THROTTLE_MS = 60 * 60 * 1000; // 1 hour
  let lastFetchTime = 0;

  // Shown above the vault while `conflict` is set.
  const conflictDiv = document.createElement("div");
  conflictDiv.className = "pm-conflict";
  conflictDiv.setAttribute("role", "alert");
  conflictDiv.style.display = "none";
  dataDiv.before(conflictDiv);

  // Shown above the vault while `passwordChanged` is set.
  const passwordChangedDiv = document.createElement("div");
  passwordChangedDiv.className = "pm-password-changed";
  passwordChangedDiv.setAttribute("role", "alert");
  passwordChangedDiv.style.display = "none";
  dataDiv.before(passwordChangedDiv);

  // ── Serial save queue ────────────────────────────────────────────────────
  // Prevents concurrent PUTs from racing; each save chains onto the previous.
  let pendingSave: Promise<void> = Promise.resolve();

  function enqueue(task: () => Promise<void>): Promise<void> {
    pendingSave = pendingSave.then(task);
    return pendingSave;
  }

  function offlineMessage(): string {
    return remembered
      ? "Offline — changes are kept on this device and saved when you're back online"
      : "Offline — changes aren't saved yet; keep this page open until you're back online";
  }

  function hasUnsavedChanges(): boolean {
    return (
      currentData != null &&
      baseData != null &&
      !vaultsEqual(currentData, baseData)
    );
  }

  /** Stores this session's state on the device if the account is remembered:
   *  the last server version, and the changes not saved to it yet. Writes are
   *  applied in the order they're started. */
  function persistState(): Promise<void> {
    if (
      !remembered ||
      currentEncryptionKey == null ||
      currentUsername == null ||
      currentData == null ||
      baseBlob == null
    )
      return Promise.resolve();
    const pendingBlob = hasUnsavedChanges()
      ? encryptBlob(
          currentEncryptionKey,
          new TextEncoder().encode(JSON.stringify(currentData)),
        )
      : null;
    return putVault({
      id: accountId(currentUsername, currentServerNs),
      syncedBlob: baseBlob,
      syncedEtag: currentEtag,
      syncedLastModified: currentLastModified,
      pendingBlob,
    }).catch((e) => {
      statSpan.textContent = `⚠ Couldn't store changes on this device: ${e}`;
    });
  }

  /** Downloads and decrypts the current server version, or returns why it
   *  couldn't. */
  async function fetchVault(): Promise<SyncedVault | string> {
    if (
      currentEncryptionKey == null ||
      currentUsername == null ||
      currentAuthKeyB64 == null ||
      currentServerPass == null
    )
      return "Not logged in";
    const download = await downloadVault(
      currentUsername,
      currentServerNs,
      currentServerPass,
      currentAuthKeyB64,
    );
    if (!download.ok) {
      if (download.reason === "offline") return offlineMessage();
      if (download.reason === "credentials") {
        showPasswordChanged();
        return "Saving paused: the password was changed";
      }
      return `Refresh failed ${download.message}`;
    }
    reachedServer = true;
    try {
      return {
        data: decodeVault(currentEncryptionKey, download.blob),
        blob: download.blob,
        etag: download.etag,
        lastModified: download.lastModified,
      };
    } catch (e) {
      return `Refresh error: ${e}`;
    }
  }

  /** Makes `latest` the new base, with `merged` as this session's data. */
  function adoptServerVersion(merged: VaultRoot, latest: SyncedVault): void {
    currentData = merged;
    baseData = latest.data;
    baseBlob = latest.blob;
    currentEtag = latest.etag;
    currentLastModified = latest.lastModified;
    render();
    void persistState();
  }

  /** After a save was refused because another session saved first: merges
   *  that session's changes into this one. Returns false (and pauses saving)
   *  if the merge found conflicts or the latest version couldn't be loaded. */
  async function mergeLatest(): Promise<boolean> {
    statSpan.textContent = "Merging changes from another session…";
    const latest = await fetchVault();
    if (typeof latest === "string") {
      statSpan.textContent = `⚠ ${latest}`;
      return false;
    }
    return mergeWith(latest);
  }

  /** Merges `latest` into this session's data; false (with saving paused) if
   *  the merge found conflicts. */
  function mergeWith(latest: SyncedVault): boolean {
    if (currentData == null || baseData == null) return false;
    const { merged, conflicts } = mergeVaults(
      baseData,
      currentData,
      latest.data,
    );
    if (conflicts.length > 0) {
      conflict = latest;
      showConflict(conflicts);
      return false;
    }
    adoptServerVersion(merged, latest);
    return true;
  }

  function showConflict(conflicts: string[]): void {
    statSpan.textContent = "⚠ Saving paused: conflicting changes";
    conflictDiv.innerHTML = "";
    const intro = document.createElement("p");
    intro.textContent =
      "This vault was changed in another session, and some of the same items were changed here too. Saving is paused until you load the latest version. Your other changes will be kept; for these items the other session's version will be used:";
    const list = document.createElement("ul");
    const SHOWN = 10;
    for (const c of conflicts.slice(0, SHOWN)) {
      const li = document.createElement("li");
      li.textContent = c;
      list.appendChild(li);
    }
    if (conflicts.length > SHOWN) {
      const li = document.createElement("li");
      li.textContent = `…and ${conflicts.length - SHOWN} more`;
      list.appendChild(li);
    }
    const loadButton = document.createElement("button");
    loadButton.type = "button";
    loadButton.className = "pm-btn";
    loadButton.textContent = "Load latest version";
    loadButton.addEventListener("click", () => resolveConflict());
    conflictDiv.append(intro, list, loadButton);
    conflictDiv.style.display = "";
  }

  function hideConflict(): void {
    conflict = null;
    conflictDiv.innerHTML = "";
    conflictDiv.style.display = "none";
  }

  /** Takes the other session's version for the conflicting items, keeps this
   *  session's other changes, and saves the result. */
  async function resolveConflict(): Promise<void> {
    const latest = conflict;
    if (latest == null || currentData == null || baseData == null) return;
    hideConflict();
    // re-merged now in case of edits made while saving was paused; the
    // conflicts resolve to the server's version
    const { merged } = mergeVaults(baseData, currentData, latest.data);
    adoptServerVersion(merged, latest);
    if (!vaultsEqual(merged, latest.data)) await saveVault();
  }

  async function saveVault(): Promise<void> {
    // stored on the device first, so the change survives the app being closed
    // or the save failing
    void persistState();
    return enqueue(async () => {
      // a save refused because another session saved first is retried after
      // merging; a few attempts cover sessions that keep saving meanwhile
      for (let attempt = 0; attempt < 3; attempt++) {
        if (
          currentEncryptionKey == null ||
          currentUsername == null ||
          currentAuthKeyB64 == null ||
          currentServerPass == null ||
          currentData == null
        )
          return;
        if (conflict != null) {
          statSpan.textContent =
            "⚠ Saving paused: load the latest version first";
          return;
        }
        if (passwordChanged) {
          statSpan.textContent =
            "⚠ Saving paused: enter the new password first";
          return;
        }

        statSpan.textContent = "Saving…";
        try {
          const json = JSON.stringify(currentData);
          const blob = encryptBlob(
            currentEncryptionKey,
            new TextEncoder().encode(json),
          );

          const url = new URL("/pass-table", window.location.origin);
          url.searchParams.set("username", currentUsername);
          if (currentServerNs != null)
            url.searchParams.set("server_ns", currentServerNs);

          const headers: Record<string, string> = {
            ...credentialHeaders(currentAuthKeyB64, currentServerPass),
            "Content-Type": "application/octet-stream",
            "Content-Length": String(blob.byteLength),
          };
          if (currentEtag != null) headers["If-Match"] = currentEtag;

          let response: Response;
          try {
            response = await fetch(url.toString(), {
              method: "PUT",
              headers,
              body: blob,
            });
          } catch {
            // no response: the change stays pending until the next save
            statSpan.textContent = offlineMessage();
            return;
          }
          reachedServer = true;

          if (response.status === 412) {
            if (!(await mergeLatest())) return;
            continue;
          }
          if (!response.ok) {
            const error = await describeError(response);
            if (error.type === "E_AUTH") {
              showPasswordChanged();
              return;
            }
            statSpan.textContent = `Save failed ${error.message}`;
            return;
          }

          currentEtag = response.headers.get("ETag");
          currentLastModified = response.headers.get("Last-Modified");
          baseData = JSON.parse(json) as VaultRoot;
          baseBlob = blob;
          void persistState();
          statSpan.textContent = currentLastModified
            ? `Last saved: ${currentLastModified}`
            : "Saved";
          return;
        } catch (e) {
          statSpan.textContent = `Save error: ${e}`;
          return;
        }
      }
      statSpan.textContent =
        "⚠ Save failed: the vault keeps changing in another session";
    });
  }

  /** Brings this session up to date with the server: merges in the latest
   *  version, then saves this session's changes, if any. */
  async function syncWithServer(): Promise<void> {
    await enqueue(async () => {
      if (conflict != null || passwordChanged) return;
      statSpan.textContent = "Checking for changes…";
      const latest = await fetchVault();
      if (typeof latest === "string") {
        statSpan.textContent = `⚠ ${latest}`;
        return;
      }
      if (latest.etag !== currentEtag) mergeWith(latest);
      else showSavedStatus();
    });
    if (hasUnsavedChanges()) await saveVault();
  }

  // Back online: save what was changed offline. If the server wasn't reached
  // since unlocking (so the vault may be out of date), merge its version too.
  window.addEventListener("online", () => {
    if (currentData == null) return;
    if (!reachedServer) void syncWithServer();
    else if (hasUnsavedChanges()) void saveVault();
  });

  function showPasswordChanged(): void {
    if (passwordChanged) return;
    passwordChanged = true;
    statSpan.textContent = "⚠ Saving paused: the password was changed";
    passwordChangedDiv.innerHTML = "";
    const intro = document.createElement("p");
    intro.textContent =
      "The password for this account was changed in another session. Enter the new password to continue saving; the changes made here will be merged with the other session's.";
    const form = document.createElement("form");
    form.method = "dialog";
    form.className = "pm-inline-form";
    const input = document.createElement("input");
    input.type = "password";
    input.name = "new-password";
    input.autocomplete = "current-password";
    input.setAttribute("aria-label", "New password");
    const submit = document.createElement("button");
    submit.type = "submit";
    submit.className = "pm-btn pm-btn-primary";
    submit.textContent = "Continue";
    const status = document.createElement("span");
    form.append(input, submit, status);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      submit.disabled = true;
      try {
        status.textContent = "Checking…";
        status.textContent = await adoptNewPassword(input.value);
      } finally {
        submit.disabled = false;
      }
    });
    passwordChangedDiv.append(intro, form);
    passwordChangedDiv.style.display = "";
  }

  function hidePasswordChanged(): void {
    passwordChanged = false;
    passwordChangedDiv.innerHTML = "";
    passwordChangedDiv.style.display = "none";
  }

  /** Switches to the password set in another session and merges that
   *  session's version. Returns an error message, or "" on success. */
  async function adoptNewPassword(password: string): Promise<string> {
    if (currentUsername == null || currentServerPass == null) return "";
    let keys: { authKeyB64: string; encryptionKey: Uint8Array };
    try {
      keys = await deriveUserKeys(currentUsername, password);
    } catch (e) {
      return `Key derivation failed: ${e}`;
    }
    const download = await downloadVault(
      currentUsername,
      currentServerNs,
      currentServerPass,
      keys.authKeyB64,
    );
    if (!download.ok) {
      if (download.reason === "credentials") return "Wrong password.";
      if (download.reason === "offline") return "Can't reach the server.";
      return `Failed ${download.message}`;
    }
    let data: VaultRoot;
    try {
      data = decodeVault(keys.encryptionKey, download.blob);
    } catch (e) {
      return `Decryption failed: ${e}`;
    }
    await enqueue(async () => {
      currentAuthKeyB64 = keys.authKeyB64;
      currentEncryptionKey = keys.encryptionKey;
      // this device's copy of the base version is re-encrypted with the new
      // key too, so it stays readable even if the merge below pauses saving
      if (baseData != null)
        baseBlob = encryptBlob(
          keys.encryptionKey,
          new TextEncoder().encode(JSON.stringify(baseData)),
        );
      hidePasswordChanged();
      mergeWith({
        data,
        blob: download.blob,
        etag: download.etag,
        lastModified: download.lastModified,
      });
      // a merge paused by conflicts doesn't store anything, so store the
      // re-encrypted copy here
      void persistState();
    });
    void keysChanged();
    if (hasUnsavedChanges()) await saveVault();
    return "";
  }

  // ── Background check for a newer version (when an edit starts) ──────────
  // Returns a notice to show, or null. It doesn't merge here, since that
  // re-renders and would cancel the edit being started; the next save merges.
  async function checkForNewerVersion(): Promise<string | null> {
    if (
      currentUsername == null ||
      currentAuthKeyB64 == null ||
      currentServerPass == null
    )
      return null;

    // Throttle: skip if we fetched recently.
    if (Date.now() - lastFetchTime < FETCH_THROTTLE_MS) return null;

    const download = await downloadVault(
      currentUsername,
      currentServerNs,
      currentServerPass,
      currentAuthKeyB64,
    );
    if (!download.ok) {
      if (download.reason === "offline") return null;
      if (download.reason === "credentials") {
        showPasswordChanged();
        return null;
      }
      return `Refresh failed ${download.message}`;
    }
    lastFetchTime = Date.now();
    if (download.etag != null && download.etag !== currentEtag)
      return "Vault updated in another session — those changes will be merged when you save";
    return null;
  }

  // ── History UI ────────────────────────────────────────────────────────────
  let historyDetails: HTMLDetailsElement | null = null;

  function describeEntry(entry: HistoryEntry): string {
    switch (entry.kind) {
      case "cell-edit":
        return `Edited "${entry.colLabel}" in "${entry.tableName}" row ${entry.rowIndex + 1}`;
      case "table-name":
        return `Renamed table "${entry.previousName}" → "${entry.newName}"`;
      case "row-add":
        return `Added row to "${entry.tableName}"`;
      case "row-delete":
        return `Deleted row ${entry.rowIndex + 1} from "${entry.tableName}"`;
      case "col-add":
        return `Added column "${entry.colLabel}" to "${entry.tableName}"`;
      case "col-delete":
        return `Deleted column "${entry.colMeta.label}" from "${entry.tableName}"`;
      case "table-add":
        return `Added table "${entry.tableName}"`;
      case "table-delete":
        return `Deleted table "${entry.tableSnapshot.name}"`;
    }
  }

  /** Mutates currentData to revert the entry; returns the inverse entry, or
   *  null if the entry can no longer be applied. */
  function revertEntry(entry: HistoryEntry): HistoryEntry | null {
    if (!currentData) return null;

    switch (entry.kind) {
      case "cell-edit": {
        const tbl = currentData.tables.find((t) => t.id === entry.tableId);
        const col = tbl?.columns.find((c) => c.id === entry.colId);
        const rowIdx = tbl?.rowIds.indexOf(entry.rowId) ?? -1;
        if (!tbl || !col || rowIdx < 0) return null;

        const currentValue = structuredClone(col.data[rowIdx]) as CellValue;
        setCellValue(col, rowIdx, entry.previousValue);

        return {
          kind: "cell-edit",
          timestamp: new Date().toISOString(),
          tableId: entry.tableId,
          tableName: entry.tableName,
          colId: entry.colId,
          colLabel: entry.colLabel,
          rowId: entry.rowId,
          rowIndex: rowIdx,
          previousValue: currentValue,
          newValue: entry.previousValue,
        };
      }

      case "table-name": {
        const tbl = currentData.tables.find((t) => t.id === entry.tableId);
        if (!tbl) return null;
        const currentName = tbl.name;
        tbl.name = entry.previousName;
        return {
          kind: "table-name",
          timestamp: new Date().toISOString(),
          tableId: entry.tableId,
          previousName: currentName,
          newName: entry.previousName,
        };
      }

      case "row-delete": {
        const tbl = currentData.tables.find((t) => t.id === entry.tableId);
        if (!tbl) return null;
        const insertIdx = Math.min(entry.rowIndex, tbl.rowIds.length);
        tbl.rowIds.splice(insertIdx, 0, entry.rowId);

        const snapMap = new Map(
          entry.cellSnapshot.map((s) => [s.colId, s.value]),
        );
        tbl.columns.forEach((col) => {
          const val = snapMap.get(col.id) ?? getDefaultCellValue(col.type);
          spliceCellValue(col, insertIdx, val);
        });

        return {
          kind: "row-add",
          timestamp: new Date().toISOString(),
          tableId: entry.tableId,
          tableName: entry.tableName,
          rowId: entry.rowId,
          rowIndex: insertIdx,
        };
      }

      case "row-add": {
        const tbl = currentData.tables.find((t) => t.id === entry.tableId);
        if (!tbl) return null;
        const rowIdx = tbl.rowIds.indexOf(entry.rowId);
        if (rowIdx < 0) return null;

        const cellSnapshot = tbl.columns.map((c) => ({
          colId: c.id,
          colLabel: c.label,
          value: structuredClone(c.data[rowIdx]) as CellValue,
        }));
        tbl.columns.forEach((c) => c.data.splice(rowIdx, 1));
        tbl.rowIds.splice(rowIdx, 1);

        return {
          kind: "row-delete",
          timestamp: new Date().toISOString(),
          tableId: entry.tableId,
          tableName: entry.tableName,
          rowId: entry.rowId,
          rowIndex: rowIdx,
          cellSnapshot,
        };
      }

      case "col-delete": {
        const tbl = currentData.tables.find((t) => t.id === entry.tableId);
        if (!tbl) return null;
        const insertIdx = Math.min(entry.colIndex, tbl.columns.length);

        const rowIdToVal = new Map(
          entry.cellsByRowId.map((c) => [c.rowId, c.value]),
        );
        const data: CellValue[] = tbl.rowIds.map(
          (rid) =>
            rowIdToVal.get(rid) ?? getDefaultCellValue(entry.colMeta.type),
        );

        let newCol: PassTableData["columns"][number];
        if (entry.colMeta.type === "textarea") {
          newCol = {
            id: entry.colMeta.id,
            label: entry.colMeta.label,
            type: "textarea",
            data: data as string[],
          };
        } else if (entry.colMeta.type === "link") {
          newCol = {
            id: entry.colMeta.id,
            label: entry.colMeta.label,
            type: "link",
            data: data as LinkCellData[],
          };
        } else {
          newCol = {
            id: entry.colMeta.id,
            label: entry.colMeta.label,
            type: "password",
            data: data as PasswordCellData[],
          };
        }
        tbl.columns.splice(insertIdx, 0, newCol);

        return {
          kind: "col-add",
          timestamp: new Date().toISOString(),
          tableId: entry.tableId,
          tableName: entry.tableName,
          colId: entry.colMeta.id,
          colLabel: entry.colMeta.label,
        };
      }

      case "col-add": {
        const tbl = currentData.tables.find((t) => t.id === entry.tableId);
        if (!tbl) return null;
        const colIdx = tbl.columns.findIndex((c) => c.id === entry.colId);
        if (colIdx < 0) return null;

        const col = tbl.columns[colIdx];
        const cellsByRowId = tbl.rowIds.map((rowId, rowIdx) => ({
          rowId,
          value: structuredClone(col.data[rowIdx]) as CellValue,
        }));
        tbl.columns.splice(colIdx, 1);

        return {
          kind: "col-delete",
          timestamp: new Date().toISOString(),
          tableId: entry.tableId,
          tableName: entry.tableName,
          colMeta: { id: col.id, label: col.label, type: col.type },
          cellsByRowId,
          colIndex: colIdx,
        };
      }

      case "table-delete": {
        const insertIdx = Math.min(entry.tableIndex, currentData.tables.length);
        const snap = structuredClone(entry.tableSnapshot) as PassTableData;
        currentData.tables.splice(insertIdx, 0, snap);
        return {
          kind: "table-add",
          timestamp: new Date().toISOString(),
          tableId: entry.tableId,
          tableName: snap.name,
        };
      }

      case "table-add": {
        const tblIdx = currentData.tables.findIndex(
          (t) => t.id === entry.tableId,
        );
        if (tblIdx < 0) return null;
        const snap = structuredClone(
          currentData.tables[tblIdx],
        ) as PassTableData;
        currentData.tables.splice(tblIdx, 1);
        return {
          kind: "table-delete",
          timestamp: new Date().toISOString(),
          tableId: entry.tableId,
          tableIndex: tblIdx,
          tableSnapshot: snap,
        };
      }
    }
  }

  function renderHistoryList(
    container: HTMLElement,
    onReverted: () => void,
  ): void {
    container.innerHTML = "";
    if (!currentData || currentData.history.length === 0) {
      const empty = document.createElement("p");
      empty.style.cssText = "color:#6b7280;font-style:italic;margin:0.5em 0";
      empty.textContent = "No history yet.";
      container.appendChild(empty);
      return;
    }

    [...currentData.history].reverse().forEach((entry) => {
      const row = document.createElement("div");
      row.className = "pm-history-entry";

      const time = new Date(entry.timestamp).toLocaleTimeString();
      const text = document.createElement("span");
      text.className = "pm-history-desc";
      text.textContent = `${time} — ${describeEntry(entry)}`;

      const revertBtn = document.createElement("button");
      revertBtn.className = "pm-btn pm-btn-ghost pm-history-revert";
      revertBtn.textContent = "Revert";
      revertBtn.addEventListener("click", async () => {
        const inverse = revertEntry(entry);
        if (inverse === null) {
          revertBtn.textContent = "No longer applicable";
          revertBtn.disabled = true;
          return;
        }
        currentData!.history.push(inverse);
        if (currentData!.history.length > 100)
          currentData!.history.splice(0, currentData!.history.length - 100);
        await saveVault();
        render();
        onReverted();
      });

      row.append(text, revertBtn);
      container.appendChild(row);
    });
  }

  function rerenderHistoryUI(): void {
    if (!historyDetails || !currentData) return;
    const summary = historyDetails.querySelector("summary")!;
    summary.textContent = `History (${currentData.history.length} entries)`;
    const list = historyDetails.querySelector(
      ".pm-history-list",
    ) as HTMLElement;
    renderHistoryList(list, () => {});
  }

  function showHistoryModal(): void {
    if (document.getElementById("pm-history-modal")) return;

    const backdrop = document.createElement("div");
    backdrop.id = "pm-history-modal";
    backdrop.className = "pm-backdrop";
    backdrop.addEventListener("click", (e) => {
      if (e.target === backdrop) backdrop.remove();
    });

    const modal = document.createElement("div");
    modal.className = "pm-modal";
    modal.style.cssText = "max-height:80vh;overflow-y:auto;min-width:480px";

    const title = document.createElement("h3");
    title.textContent = `History (${currentData?.history.length ?? 0} entries)`;

    const list = document.createElement("div");
    list.className = "pm-history-list";
    renderHistoryList(list, () => {
      // Update modal title after revert
      title.textContent = `History (${currentData?.history.length ?? 0} entries)`;
      renderHistoryList(list, () => {});
    });

    const footer = document.createElement("div");
    footer.className = "pm-modal-footer";
    const closeBtn = document.createElement("button");
    closeBtn.className = "pm-btn pm-btn-ghost";
    closeBtn.type = "button";
    closeBtn.textContent = "Close";
    closeBtn.addEventListener("click", () => backdrop.remove());
    footer.appendChild(closeBtn);

    modal.append(title, list, footer);
    backdrop.appendChild(modal);
    document.body.appendChild(backdrop);
  }

  // ── Callbacks passed to every renderPassTable call ────────────────────────
  const callbacks: PassTableCallbacks = {
    onFetchBeforeEdit: () => {
      // Fire a background refresh — do NOT block edit mode entry on it.
      checkForNewerVersion().then((notice) => {
        if (notice != null) statSpan.textContent = `⚠ ${notice}`;
      });
      return Promise.resolve();
    },
    onAction: async (entry: HistoryEntry) => {
      if (!currentData) return;
      currentData.history.push(entry);
      if (currentData.history.length > 100)
        currentData.history.splice(0, currentData.history.length - 100);
      await saveVault();
      rerenderHistoryUI();
    },
  };

  // ── Render ────────────────────────────────────────────────────────────────
  function showSavedStatus(): void {
    statSpan.textContent = currentLastModified
      ? `Last saved: ${currentLastModified}`
      : "Unsaved";
  }

  function render(): void {
    if (currentData == null) return;
    dataDiv.innerHTML = "";
    showSavedStatus();

    currentData.tables.forEach((table) => {
      const tableDiv = document.createElement("div");
      renderPassTable(table, tableDiv, callbacks, () => {
        const tableSnapshot = structuredClone(table) as PassTableData;
        const idx = currentData!.tables.indexOf(table);
        tableDiv.remove();
        currentData!.tables.splice(idx, 1);
        callbacks.onAction({
          kind: "table-delete",
          timestamp: new Date().toISOString(),
          tableId: table.id,
          tableIndex: idx,
          tableSnapshot,
        });
      });
      dataDiv.appendChild(tableDiv);
    });

    const addButton = document.createElement("button");
    addButton.className = "pm-add-btn";
    addButton.style.marginTop = "0.25em";
    addButton.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4.5v15m7.5-7.5h-15"/></svg>Add Table`;
    addButton.addEventListener("click", async () => {
      const table: PassTableData = {
        id: crypto.randomUUID(),
        rowIds: [],
        name: "New Table",
        columns: [],
      };
      currentData!.tables.push(table);
      const tableDiv = document.createElement("div");
      renderPassTable(table, tableDiv, callbacks, () => {
        const tableSnapshot = structuredClone(table) as PassTableData;
        const idx = currentData!.tables.indexOf(table);
        tableDiv.remove();
        currentData!.tables.splice(idx, 1);
        callbacks.onAction({
          kind: "table-delete",
          timestamp: new Date().toISOString(),
          tableId: table.id,
          tableIndex: idx,
          tableSnapshot,
        });
      });
      dataDiv.insertBefore(tableDiv, addButton);
      await callbacks.onAction({
        kind: "table-add",
        timestamp: new Date().toISOString(),
        tableId: table.id,
        tableName: table.name,
      });
    });
    dataDiv.appendChild(addButton);

    // ── History panel ───────────────────────────────────────────────────────
    const details = document.createElement("details");
    details.name = "history";
    details.className = "pm-history-details";
    details.style.marginTop = "1.5em";
    const summary = document.createElement("summary");
    summary.textContent = `History (${currentData.history.length} entries)`;
    const list = document.createElement("div");
    list.className = "pm-history-list";
    list.style.cssText = "margin-top:0.5em";
    details.addEventListener("toggle", () => {
      if (details.open) renderHistoryList(list, () => {});
    });
    details.append(summary, list);
    dataDiv.appendChild(details);
    historyDetails = details;
  }

  // ── Button wiring ─────────────────────────────────────────────────────────
  saveButton.addEventListener("click", () => saveVault());

  historyButton?.addEventListener("click", () => showHistoryModal());

  // ── Change Password ───────────────────────────────────────────────────────
  const changePassDetails = contentDiv.querySelector(
    "details[name='change-password']",
  ) as HTMLDetailsElement;
  const changePassForm = changePassDetails.querySelector("form")!;
  const currentPassInput = changePassForm.querySelector(
    "input[name='current_pass']",
  ) as HTMLInputElement;
  const newPassChgInput = changePassForm.querySelector(
    "input[name='new_pass_chg']",
  ) as HTMLInputElement;
  const confirmNewPassChgInput = changePassForm.querySelector(
    "input[name='confirm_new_pass_chg']",
  ) as HTMLInputElement;
  const showCurrentPassChk = changePassForm.querySelector(
    "input[name='show-current-pass']",
  ) as HTMLInputElement;
  const showNewPassChgChk = changePassForm.querySelector(
    "input[name='show-new-pass-chg']",
  ) as HTMLInputElement;
  const chgPassStatus = changePassForm.querySelector(
    "span[name='chg-pass-status']",
  ) as HTMLSpanElement;
  const chgPassSubmit = changePassForm.querySelector(
    "input[name='submit-chg-pass']",
  ) as HTMLInputElement;

  showCurrentPassChk.addEventListener("change", () => {
    currentPassInput.type = showCurrentPassChk.checked ? "text" : "password";
  });
  showNewPassChgChk.addEventListener("change", () => {
    const t = showNewPassChgChk.checked ? "text" : "password";
    newPassChgInput.type = t;
    confirmNewPassChgInput.type = t;
  });

  chgPassSubmit.addEventListener("click", async (event) => {
    event.preventDefault();
    chgPassStatus.textContent = "";

    if (
      currentUsername == null ||
      currentEncryptionKey == null ||
      currentAuthKeyB64 == null ||
      currentServerPass == null ||
      currentData == null ||
      currentEtag == null
    ) {
      chgPassStatus.textContent = "Not logged in.";
      return;
    }

    const currentPass = currentPassInput.value;
    const newPass = newPassChgInput.value;
    const confirmPass = confirmNewPassChgInput.value;

    if (!currentPass) {
      chgPassStatus.textContent = "Please enter your current password.";
      return;
    }
    if (!newPass) {
      chgPassStatus.textContent = "New password cannot be empty.";
      return;
    }
    if (newPass !== confirmPass) {
      chgPassStatus.textContent = "New passwords do not match.";
      return;
    }

    chgPassStatus.textContent = "Deriving keys…";
    let oldAuthKeyB64: string;
    let newAuthKeyB64: string;
    let newEncryptionKey: Uint8Array;
    try {
      ({ authKeyB64: oldAuthKeyB64 } = await deriveUserKeys(
        currentUsername,
        currentPass,
      ));
      ({ authKeyB64: newAuthKeyB64, encryptionKey: newEncryptionKey } =
        await deriveUserKeys(currentUsername, newPass));
    } catch (e) {
      chgPassStatus.textContent = `Key derivation failed: ${e}`;
      return;
    }

    const serverPass = currentServerPass;
    const url = new URL("/pass-table-new-pass", window.location.origin);
    url.searchParams.set("username", currentUsername);
    if (currentServerNs != null)
      url.searchParams.set("server_ns", currentServerNs);

    // queued with saves, so a save still using the old key can't run after it
    await enqueue(async () => {
      // if another session saved first, merge its changes and try once more
      for (let attempt = 0; attempt < 2; attempt++) {
        if (currentData == null || currentEtag == null) return;
        if (conflict != null) {
          chgPassStatus.textContent =
            "Load the latest version of the vault (see above), then try again.";
          return;
        }
        chgPassStatus.textContent = "Encrypting…";
        const json = JSON.stringify(currentData);
        const blob = encryptBlob(
          newEncryptionKey,
          new TextEncoder().encode(json),
        );

        chgPassStatus.textContent = "Saving…";
        let response: Response;
        try {
          response = await fetch(url.toString(), {
            method: "PUT",
            headers: {
              ...credentialHeaders(oldAuthKeyB64, serverPass),
              "Passman-New-Auth-Key": newAuthKeyB64,
              "Content-Type": "application/octet-stream",
              "Content-Length": String(blob.byteLength),
              "If-Match": currentEtag,
            },
            body: blob,
          });
        } catch (e) {
          chgPassStatus.textContent = `Network error: ${e}`;
          return;
        }

        if (response.status === 412) {
          chgPassStatus.textContent = "Merging changes from another session…";
          if (!(await mergeLatest())) {
            chgPassStatus.textContent =
              "The vault was changed in another session; resolve that, then try again.";
            return;
          }
          continue;
        }
        if (!response.ok) {
          chgPassStatus.textContent = `Change password failed ${(await describeError(response)).message}`;
          return;
        }

        currentAuthKeyB64 = newAuthKeyB64;
        currentEncryptionKey = newEncryptionKey;
        currentEtag = response.headers.get("ETag");
        currentLastModified = response.headers.get("Last-Modified");
        baseData = JSON.parse(json) as VaultRoot;
        baseBlob = blob;
        // re-encrypts this device's copy with the new key
        void persistState();
        void keysChanged();
        statSpan.textContent = currentLastModified
          ? `Last saved: ${currentLastModified}`
          : "Saved";

        currentPassInput.value = "";
        newPassChgInput.value = "";
        confirmNewPassChgInput.value = "";
        changePassDetails.open = false;
        chgPassStatus.textContent = "Password changed successfully.";
        return;
      }
      chgPassStatus.textContent =
        "Change password failed: the vault keeps changing in another session.";
    });
  });

  // ── This Device ───────────────────────────────────────────────────────────
  const deviceDetails = contentDiv.querySelector(
    "details[name='this-device']",
  ) as HTMLDetailsElement;
  const deviceStatus = deviceDetails.querySelector(
    "[name='device-status']",
  ) as HTMLElement;
  const rememberButton = deviceDetails.querySelector(
    "button[name='remember-device']",
  ) as HTMLButtonElement;
  const forgetButton = deviceDetails.querySelector(
    "button[name='forget-device']",
  ) as HTMLButtonElement;

  const biometricDiv = deviceDetails.querySelector(
    "[name='biometric']",
  ) as HTMLElement;
  const biometricStatus = biometricDiv.querySelector(
    "[name='biometric-status']",
  ) as HTMLElement;
  const biometricMessage = biometricDiv.querySelector(
    "[name='biometric-message']",
  ) as HTMLElement;
  const enableBiometricButton = biometricDiv.querySelector(
    "button[name='enable-biometric']",
  ) as HTMLButtonElement;
  const updateBiometricButton = biometricDiv.querySelector(
    "button[name='update-biometric']",
  ) as HTMLButtonElement;
  const disableBiometricButton = biometricDiv.querySelector(
    "button[name='disable-biometric']",
  ) as HTMLButtonElement;

  function renderDeviceSection(): void {
    deviceStatus.textContent = remembered
      ? "This account is remembered on this device: it can be unlocked offline, and changes made offline are saved when you're back online."
      : "This account isn't stored on this device: it needs a connection to unlock, and nothing is kept after you log out.";
    rememberButton.style.display = remembered ? "none" : "";
    forgetButton.style.display = remembered ? "" : "none";
    void renderBiometricSection();
  }

  /** Biometric unlock needs the account to be remembered: it unlocks the copy
   *  on this device. */
  async function renderBiometricSection(): Promise<void> {
    const shown = (button: HTMLElement, show: boolean) =>
      (button.style.display = show ? "" : "none");
    if (!remembered || currentUsername == null) {
      biometricDiv.style.display = "none";
      return;
    }
    const id = accountId(currentUsername, currentServerNs);
    const [supported, status] = await Promise.all([
      keyProtector.isSupported(),
      keyProtector.status(id).catch(() => null),
    ]);
    // the session may have ended (or switched) meanwhile
    if (
      currentUsername == null ||
      accountId(currentUsername, currentServerNs) !== id
    )
      return;
    biometricDiv.style.display = "";
    if (status == null) {
      biometricStatus.textContent = supported
        ? "Unlock this account with Face ID, Touch ID or a fingerprint instead of the password. The device's passcode also works if biometrics fail."
        : "Biometric unlock isn't available in this browser.";
    } else if (status.current) {
      biometricStatus.textContent =
        "Biometric unlock is on." +
        (status.synced === true
          ? " Its passkey syncs with your Apple or Google account, but it only works together with a key kept on this device."
          : status.synced === false
            ? " Its passkey is stored only on this device."
            : "");
    } else {
      biometricStatus.textContent =
        "Biometric unlock needs to be confirmed again (the password was changed, or setting it up wasn't finished).";
    }
    shown(enableBiometricButton, status == null && supported);
    shown(updateBiometricButton, status != null && !status.current);
    shown(disableBiometricButton, status != null);
  }

  /** Called when this session's keys changed (the password was changed):
   *  biometric unlock still holds the old ones until it is confirmed again. */
  async function keysChanged(): Promise<void> {
    if (currentUsername == null) return;
    try {
      await keyProtector.invalidate(
        accountId(currentUsername, currentServerNs),
      );
    } catch (e) {
      biometricMessage.textContent = `⚠ ${e}`;
    }
    void renderBiometricSection();
  }

  async function protectKeys(): Promise<void> {
    if (
      currentUsername == null ||
      currentAuthKeyB64 == null ||
      currentEncryptionKey == null
    )
      return;
    const label = currentServerNs
      ? `${currentUsername} (${currentServerNs})`
      : currentUsername;
    biometricMessage.textContent = "Waiting for biometrics…";
    try {
      await keyProtector.protect(
        accountId(currentUsername, currentServerNs),
        label,
        {
          authKeyB64: currentAuthKeyB64,
          encryptionKey: currentEncryptionKey,
        },
      );
      biometricMessage.textContent = "";
    } catch (e) {
      biometricMessage.textContent = unlockErrorMessage(e);
    }
    await renderBiometricSection();
  }

  enableBiometricButton.addEventListener("click", () => protectKeys());
  updateBiometricButton.addEventListener("click", () => protectKeys());
  disableBiometricButton.addEventListener("click", async () => {
    if (currentUsername == null) return;
    try {
      await keyProtector.remove(accountId(currentUsername, currentServerNs));
      biometricMessage.textContent = "";
    } catch (e) {
      biometricMessage.textContent = `⚠ ${e}`;
    }
    await renderBiometricSection();
  });

  /** Records the account in the device's list (or updates its server password
   *  and last use) and stores the current state. */
  async function rememberAccount(): Promise<void> {
    if (currentUsername == null || currentServerPass == null) return;
    remembered = true;
    renderDeviceSection();
    try {
      await putAccount({
        id: accountId(currentUsername, currentServerNs),
        username: currentUsername,
        serverNs: currentServerNs,
        serverPass: currentServerPass,
        lastUsed: Date.now(),
      });
    } catch (e) {
      statSpan.textContent = `⚠ Couldn't remember this account on this device: ${e}`;
      return;
    }
    await persistState();
    void requestPersistentStorage();
  }

  rememberButton.addEventListener("click", () => rememberAccount());

  forgetButton.addEventListener("click", async () => {
    if (currentUsername == null) return;
    if (
      hasUnsavedChanges() &&
      !window.confirm(
        "Some changes haven't been saved to the server yet. They'll be lost if you log out after forgetting this account on this device. Forget it anyway?",
      )
    )
      return;
    remembered = false;
    renderDeviceSection();
    try {
      const id = accountId(currentUsername, currentServerNs);
      await keyProtector.remove(id);
      await forgetAccount(id);
    } catch (e) {
      statSpan.textContent = `⚠ Couldn't remove this account from this device: ${e}`;
    }
  });

  logoutButton.addEventListener("click", () => {
    currentEncryptionKey = null;
    currentUsername = null;
    currentAuthKeyB64 = null;
    currentServerPass = null;
    currentServerNs = null;
    currentLastModified = null;
    currentData = null;
    currentEtag = null;
    baseData = null;
    baseBlob = null;
    remembered = false;
    reachedServer = false;
    hideConflict();
    hidePasswordChanged();
    historyDetails = null;
    lastFetchTime = 0;
    // hiding is not enough: the decrypted vault would stay in the DOM
    dataDiv.innerHTML = "";
    statSpan.textContent = "";
    document
      .querySelectorAll(".pm-backdrop")
      .forEach((modal) => modal.remove());
    currentPassInput.value = "";
    newPassChgInput.value = "";
    confirmNewPassChgInput.value = "";
    chgPassStatus.textContent = "";
    changePassDetails.open = false;
    deviceDetails.open = false;
    biometricMessage.textContent = "";
    contentDiv.style.display = "none";
    onLogout();
  });

  return {
    getCurrentData(): VaultRoot | null {
      return currentData;
    },

    async recordChanges(entries: HistoryEntry[]): Promise<void> {
      if (!currentData) return;
      currentData.history.push(...entries);
      if (currentData.history.length > 100)
        currentData.history.splice(0, currentData.history.length - 100);
      render();
      await saveVault();
    },

    show({
      username,
      serverPass,
      serverNs,
      authKeyB64,
      encryptionKey,
      synced,
      pending,
      remember,
      fromCache,
      keysChanged: changed,
    }: LoginResult): void {
      currentEncryptionKey = encryptionKey;
      currentUsername = username;
      currentAuthKeyB64 = authKeyB64;
      currentServerPass = serverPass;
      currentServerNs = serverNs;
      currentLastModified = synced.lastModified;
      currentData = pending ?? structuredClone(synced.data);
      currentEtag = synced.etag;
      baseData = synced.data;
      baseBlob = synced.blob;
      reachedServer = !fromCache;
      contentDiv.style.display = "";
      render();
      remembered = remember;
      renderDeviceSection();
      if (remember) void rememberAccount();
      if (changed) void keysChanged();
      // the copy on this device may be out of date
      if (fromCache) void syncWithServer();
    },
  };
}
