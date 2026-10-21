// The Import & Export section: encrypted backups, unencrypted exports and
// importing files (see vaultTransfer.ts).

import type { HistoryEntry, PassTableData } from "./PassTable";
import {
  ImportError,
  countEntries,
  encryptBackup,
  exportTables,
  prepareForVault,
  readImportFile,
} from "./vaultTransfer";

export interface ImportExportPanelHandle {
  /** Forgets passwords and anything read from a file (on locking). */
  clear(): void;
}

export function initImportExportPanel(
  getTables: () => PassTableData[] | null,
  recordChanges: (entries: HistoryEntry[]) => Promise<void>,
  suspendAutoLock: (task: () => Promise<void>) => Promise<void>,
): ImportExportPanelHandle {
  const details = document.querySelector(
    "details[name='import-export']",
  ) as HTMLDetailsElement;
  const field = <T extends Element>(selector: string) =>
    details.querySelector(selector) as T;

  // ── Encrypted backup ──────────────────────────────────────────────────────
  const backupForm = field<HTMLFormElement>("form[name='backup']");
  const backupPass = field<HTMLInputElement>("input[name='backup-pass']");
  const backupConfirm = field<HTMLInputElement>(
    "input[name='backup-pass-confirm']",
  );
  const backupButton = field<HTMLButtonElement>(
    "button[name='download-backup']",
  );
  const backupStatus = field<HTMLElement>("[name='backup-status']");

  backupForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const tables = getTables();
    if (tables == null) return;
    if (tables.length === 0) {
      backupStatus.textContent = "There's nothing to back up yet.";
      return;
    }
    if (!backupPass.value) {
      backupStatus.textContent = "Choose a password for the backup.";
      return;
    }
    if (backupPass.value !== backupConfirm.value) {
      backupStatus.textContent = "The passwords don't match.";
      return;
    }
    backupButton.disabled = true;
    backupStatus.textContent = "Encrypting…";
    try {
      await nextFrame(); // show the status: deriving the key takes a moment
      download(
        `passman-backup-${today()}.passman`,
        encryptBackup(tables, backupPass.value),
        "application/octet-stream",
      );
      backupPass.value = backupConfirm.value = "";
      backupStatus.textContent =
        "Backup downloaded. Keep its password safe: the backup can't be opened without it.";
    } catch (e) {
      backupStatus.textContent = `Couldn't create the backup: ${e}`;
    } finally {
      backupButton.disabled = false;
    }
  });

  // ── Unencrypted export ────────────────────────────────────────────────────
  field<HTMLButtonElement>("button[name='download-export']").addEventListener(
    "click",
    () => {
      const tables = getTables();
      if (tables == null) return;
      if (
        !confirm(
          "This file won't be encrypted: anyone who gets it can read all your passwords. Delete it once you've imported it elsewhere.\n\nDownload it?",
        )
      )
        return;
      download(
        `passman-export-${today()}.json`,
        exportTables(tables),
        "application/json",
      );
    },
  );

  // ── Import ────────────────────────────────────────────────────────────────
  const importForm = field<HTMLFormElement>("form[name='import']");
  const fileInput = field<HTMLInputElement>("input[name='import-file']");
  const unlockField = field<HTMLElement>("[name='import-unlock']");
  const importPass = field<HTMLInputElement>("input[name='import-pass']");
  const preview = field<HTMLElement>("[name='import-preview']");
  const unlockButton = field<HTMLButtonElement>("button[name='unlock-import']");
  const importButton = field<HTMLButtonElement>(
    "button[name='confirm-import']",
  );
  const cancelButton = field<HTMLButtonElement>("button[name='cancel-import']");
  const importStatus = field<HTMLElement>("[name='import-status']");

  /** A backup waiting for its password. */
  let unlockBackup: ((password: string) => PassTableData[]) | null = null;
  /** Tables read from the file, waiting to be confirmed. */
  let pending: PassTableData[] | null = null;

  function resetImport(): void {
    unlockBackup = null;
    pending = null;
    importPass.value = "";
    fileInput.value = "";
    preview.replaceChildren();
    for (const el of [
      unlockField,
      preview,
      unlockButton,
      importButton,
      cancelButton,
    ])
      el.hidden = true;
  }

  function showPreview(tables: PassTableData[], warnings: string[]): void {
    unlockBackup = null;
    importPass.value = "";
    unlockField.hidden = unlockButton.hidden = true;
    if (tables.length === 0) {
      importStatus.textContent = "The file has nothing to import.";
      resetImport();
      return;
    }
    pending = tables;
    const entries = countEntries(tables);
    const summary = document.createElement("p");
    summary.textContent = `${entries} ${entries === 1 ? "entry" : "entries"} in ${tables.length} ${tables.length === 1 ? "table" : "tables"}:`;
    const names = document.createElement("ul");
    for (const table of tables) {
      const item = document.createElement("li");
      item.textContent = table.name;
      names.append(item);
    }
    preview.replaceChildren(summary, names);
    for (const warning of warnings) {
      const p = document.createElement("p");
      p.className = "pm-import-warning";
      p.textContent = `⚠ ${warning}`;
      preview.append(p);
    }
    preview.hidden = importButton.hidden = cancelButton.hidden = false;
    importButton.focus();
  }

  // choosing a file can hide the app (the system file picker on phones), so
  // don't lock meanwhile
  fileInput.addEventListener("click", () => {
    void suspendAutoLock(() => pickerClosed(fileInput));
  });

  fileInput.addEventListener("change", async () => {
    const file = fileInput.files?.[0];
    importStatus.textContent = "";
    unlockBackup = null;
    pending = null;
    preview.hidden = importButton.hidden = true;
    if (file == null) return;
    try {
      const source = await readImportFile(file);
      if (source.kind === "backup") {
        unlockBackup = source.unlock;
        unlockField.hidden = unlockButton.hidden = cancelButton.hidden = false;
        importPass.focus();
      } else {
        showPreview(source.tables, source.warnings);
      }
    } catch (e) {
      resetImport();
      importStatus.textContent =
        e instanceof ImportError ? e.message : `Couldn't read the file: ${e}`;
    }
  });

  importForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (unlockBackup != null) {
      unlockButton.disabled = true;
      importStatus.textContent = "Opening…";
      try {
        await nextFrame();
        const tables = unlockBackup(importPass.value);
        importStatus.textContent = "";
        showPreview(tables, []);
      } catch (e) {
        importStatus.textContent =
          e instanceof ImportError ? e.message : `Couldn't open it: ${e}`;
        importPass.select();
      } finally {
        unlockButton.disabled = false;
      }
      return;
    }
    const current = getTables();
    if (pending == null || current == null) return;
    const added = prepareForVault(
      pending,
      current.map((table) => table.name),
    );
    const entries = countEntries(added);
    current.push(...added);
    resetImport();
    importStatus.textContent = `Imported ${entries} ${entries === 1 ? "entry" : "entries"}. To undo, revert "Added table" in History.`;
    const timestamp = new Date().toISOString();
    await recordChanges(
      added.map((table) => ({
        kind: "table-add",
        timestamp,
        tableId: table.id,
        tableName: table.name,
      })),
    );
  });

  cancelButton.addEventListener("click", () => {
    resetImport();
    importStatus.textContent = "";
  });

  return {
    clear(): void {
      resetImport();
      backupPass.value = backupConfirm.value = "";
      backupStatus.textContent = importStatus.textContent = "";
      details.open = false;
    },
  };
}

/** Resolves once the file picker opened from `input` has closed. */
function pickerClosed(input: HTMLInputElement): Promise<void> {
  return new Promise((resolve) => {
    const done = () => {
      input.removeEventListener("change", done);
      input.removeEventListener("cancel", done);
      window.removeEventListener("focus", done);
      resolve();
    };
    input.addEventListener("change", done);
    input.addEventListener("cancel", done);
    // browsers without the cancel event: the window gets focus back
    window.addEventListener("focus", done);
  });
}

function download(fileName: string, text: string, type: string): void {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

const today = () => new Date().toISOString().slice(0, 10);

const nextFrame = () =>
  new Promise<void>((resolve) =>
    requestAnimationFrame(() => setTimeout(resolve)),
  );
