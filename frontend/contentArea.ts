import type { LoginResult } from "./loginArea";
import {
  credentialHeaders,
  decodeVault,
  deriveUserKeys,
  readServerAccessParams,
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
  // Set when a merge found changes made in both sessions; saving is paused
  // until the user loads the latest version.
  let conflict: FetchedVault | null = null;
  // Throttle: only fetch from server if this many ms have elapsed since last fetch.
  const FETCH_THROTTLE_MS = 60 * 60 * 1000; // 1 hour
  let lastFetchTime = 0;

  // Shown above the vault while `conflict` is set.
  const conflictDiv = document.createElement("div");
  conflictDiv.className = "pm-conflict";
  conflictDiv.setAttribute("role", "alert");
  conflictDiv.style.display = "none";
  dataDiv.before(conflictDiv);

  // ── Serial save queue ────────────────────────────────────────────────────
  // Prevents concurrent PUTs from racing; each save chains onto the previous.
  let pendingSave: Promise<void> = Promise.resolve();

  function enqueue(task: () => Promise<void>): Promise<void> {
    pendingSave = pendingSave.then(task);
    return pendingSave;
  }

  async function describeError(response: Response): Promise<string> {
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      body = await response.text();
    }
    return `(${response.status}): ${JSON.stringify(body)}`;
  }

  interface FetchedVault {
    data: VaultRoot;
    etag: string | null;
    lastModified: string | null;
  }

  /** Downloads and decrypts the current server version, or returns an error
   *  message. */
  async function fetchVault(): Promise<FetchedVault | string> {
    if (
      currentEncryptionKey == null ||
      currentUsername == null ||
      currentAuthKeyB64 == null ||
      currentServerPass == null
    )
      return "Not logged in";
    try {
      const url = new URL("/pass-table", window.location.origin);
      url.searchParams.set("username", currentUsername);
      if (currentServerNs != null)
        url.searchParams.set("server_ns", currentServerNs);
      const response = await fetch(url.toString(), {
        headers: credentialHeaders(currentAuthKeyB64, currentServerPass),
      });
      if (!response.ok)
        return `Refresh failed ${await describeError(response)}`;
      const blob = new Uint8Array(await response.arrayBuffer());
      return {
        data: decodeVault(currentEncryptionKey, blob),
        etag: response.headers.get("ETag"),
        lastModified: response.headers.get("Last-Modified"),
      };
    } catch (e) {
      return `Refresh error: ${e}`;
    }
  }

  /** Makes `latest` the new base, with `merged` as this session's data. */
  function adoptServerVersion(merged: VaultRoot, latest: FetchedVault): void {
    currentData = merged;
    baseData = latest.data;
    currentEtag = latest.etag;
    currentLastModified = latest.lastModified;
    render();
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

          const response = await fetch(url.toString(), {
            method: "PUT",
            headers,
            body: blob,
          });

          if (response.status === 412) {
            if (!(await mergeLatest())) return;
            continue;
          }
          if (!response.ok) {
            statSpan.textContent = `Save failed ${await describeError(response)}`;
            return;
          }

          currentEtag = response.headers.get("ETag");
          currentLastModified = response.headers.get("Last-Modified");
          baseData = JSON.parse(json) as VaultRoot;
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

    try {
      const url = new URL("/pass-table", window.location.origin);
      url.searchParams.set("username", currentUsername);
      if (currentServerNs != null)
        url.searchParams.set("server_ns", currentServerNs);

      const response = await fetch(url.toString(), {
        headers: credentialHeaders(currentAuthKeyB64, currentServerPass),
      });
      if (!response.ok) return `Refresh failed (${response.status})`;

      lastFetchTime = Date.now();
      const etag = response.headers.get("ETag");
      if (etag != null && etag !== currentEtag)
        return "Vault updated in another session — those changes will be merged when you save";
      return null;
    } catch (e) {
      return `Refresh error: ${e}`;
    }
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
  function render(): void {
    if (currentData == null) return;
    dataDiv.innerHTML = "";
    statSpan.textContent = currentLastModified
      ? `Last saved: ${currentLastModified}`
      : "Unsaved";

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

    const { serverPass, serverNs } = readServerAccessParams();
    const url = new URL("/pass-table-new-pass", window.location.origin);
    url.searchParams.set("username", currentUsername);
    if (serverNs != null) url.searchParams.set("server_ns", serverNs);

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
          chgPassStatus.textContent = `Change password failed ${await describeError(response)}`;
          return;
        }

        currentAuthKeyB64 = newAuthKeyB64;
        currentEncryptionKey = newEncryptionKey;
        currentEtag = response.headers.get("ETag");
        currentLastModified = response.headers.get("Last-Modified");
        baseData = JSON.parse(json) as VaultRoot;
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
    hideConflict();
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
      data,
      lastModified,
      encryptionKey,
      username,
      authKeyB64,
      serverPass,
      serverNs,
      etag,
    }: LoginResult): void {
      currentEncryptionKey = encryptionKey;
      currentUsername = username;
      currentAuthKeyB64 = authKeyB64;
      currentServerPass = serverPass;
      currentServerNs = serverNs;
      currentLastModified = lastModified;
      currentData = data;
      currentEtag = etag;
      baseData = structuredClone(data);
      contentDiv.style.display = "";
      render();
    },
  };
}
