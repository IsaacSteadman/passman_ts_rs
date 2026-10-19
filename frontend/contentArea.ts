import type { LoginResult } from "./loginArea";
import {
  credentialHeaders,
  deriveUserKeys,
  readServerAccessParams,
} from "./loginArea";
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
  // Throttle: only fetch from server if this many ms have elapsed since last fetch.
  const FETCH_THROTTLE_MS = 60 * 60 * 1000; // 1 hour
  let lastFetchTime = 0;

  // ── Serial save queue ────────────────────────────────────────────────────
  // Prevents concurrent PUTs from racing; each save chains onto the previous.
  let pendingSave: Promise<void> = Promise.resolve();

  async function saveVault(): Promise<void> {
    pendingSave = pendingSave.then(async () => {
      if (
        currentEncryptionKey == null ||
        currentUsername == null ||
        currentAuthKeyB64 == null ||
        currentServerPass == null ||
        currentData == null
      )
        return;

      statSpan.textContent = "Saving…";
      try {
        const plaintext = new TextEncoder().encode(JSON.stringify(currentData));
        const blob = encryptBlob(currentEncryptionKey, plaintext);

        const url = new URL("/pass-table", window.location.origin);
        url.searchParams.set("username", currentUsername);
        if (currentServerNs != null)
          url.searchParams.set("server_ns", currentServerNs);

        const headers: Record<string, string> = {
          ...credentialHeaders(currentAuthKeyB64, currentServerPass),
          "Content-Type": "application/octet-stream",
          "Content-Length": String(blob.byteLength),
        };
        if (currentLastModified != null)
          headers["If-Unmodified-Since"] = currentLastModified;

        const response = await fetch(url.toString(), {
          method: "PUT",
          headers,
          body: blob,
        });

        if (!response.ok) {
          let body: unknown;
          try {
            body = await response.json();
          } catch {
            body = await response.text();
          }
          statSpan.textContent = `Save failed (${response.status}): ${JSON.stringify(body)}`;
          return;
        }

        currentLastModified =
          response.headers.get("Last-Modified") ?? currentLastModified;
        statSpan.textContent = currentLastModified
          ? `Last saved: ${currentLastModified}`
          : "Saved";
      } catch (e) {
        statSpan.textContent = `Save error: ${e}`;
      }
    });
    return pendingSave;
  }

  // ── Fetch latest vault (refresh If-Unmodified-Since before editing) ───────
  // Returns null if no fetch was needed / no conflict, "conflict" if the server
  // has a newer version than we last saw, or an error string on failure.
  async function fetchLatestVault(): Promise<string | null> {
    if (
      currentEncryptionKey == null ||
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
      const newLastModified = response.headers.get("Last-Modified");
      if (newLastModified && newLastModified !== currentLastModified) {
        currentLastModified = newLastModified;
        return "conflict";
      }
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
      fetchLatestVault().then((result) => {
        if (result === "conflict") {
          statSpan.textContent =
            "⚠ Vault updated in another session — saving will overwrite those changes";
        } else if (result != null) {
          statSpan.textContent = `⚠ ${result}`;
        }
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
      currentLastModified == null
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

    chgPassStatus.textContent = "Encrypting…";
    const plaintext = new TextEncoder().encode(JSON.stringify(currentData));
    const blob = encryptBlob(newEncryptionKey, plaintext);

    const { serverPass, serverNs } = readServerAccessParams();
    const url = new URL("/pass-table-new-pass", window.location.origin);
    url.searchParams.set("username", currentUsername);
    if (serverNs != null) url.searchParams.set("server_ns", serverNs);

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
          "If-Unmodified-Since": currentLastModified,
        },
        body: blob,
      });
    } catch (e) {
      chgPassStatus.textContent = `Network error: ${e}`;
      return;
    }

    if (!response.ok) {
      let body: unknown;
      try {
        body = await response.json();
      } catch {
        body = await response.text();
      }
      chgPassStatus.textContent = `Change password failed (${response.status}): ${JSON.stringify(body)}`;
      return;
    }

    currentAuthKeyB64 = newAuthKeyB64;
    currentEncryptionKey = newEncryptionKey;
    currentLastModified =
      response.headers.get("Last-Modified") ?? currentLastModified;
    statSpan.textContent = currentLastModified
      ? `Last saved: ${currentLastModified}`
      : "Saved";

    currentPassInput.value = "";
    newPassChgInput.value = "";
    confirmNewPassChgInput.value = "";
    changePassDetails.open = false;
    chgPassStatus.textContent = "Password changed successfully.";
  });

  logoutButton.addEventListener("click", () => {
    currentEncryptionKey = null;
    currentUsername = null;
    currentAuthKeyB64 = null;
    currentServerPass = null;
    currentServerNs = null;
    currentLastModified = null;
    currentData = null;
    historyDetails = null;
    contentDiv.style.display = "none";
    onLogout();
  });

  return {
    getCurrentData(): VaultRoot | null {
      return currentData;
    },

    show({
      data,
      lastModified,
      encryptionKey,
      username,
      authKeyB64,
      serverPass,
      serverNs,
    }: LoginResult): void {
      currentEncryptionKey = encryptionKey;
      currentUsername = username;
      currentAuthKeyB64 = authKeyB64;
      currentServerPass = serverPass;
      currentServerNs = serverNs;
      currentLastModified = lastModified;
      currentData = data;
      contentDiv.style.display = "";
      render();
    },
  };
}
