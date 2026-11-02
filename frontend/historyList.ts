// The list of a vault's history entries, newest first, used for the user's
// own vault and for shared vaults: each entry can be reverted (where the
// vault allows it), and entries picked with their checkboxes (shift-click
// picks a range) can be deleted, taking the values they hold (such as a
// password from before an edit) out of the history.

import { type HistoryEntry, describeHistoryEntry } from "./PassTable";

export interface HistoryListOptions {
  /** Oldest first, as the vault keeps them. */
  entries: HistoryEntry[];
  /** Deletes the entries the user picked (after asking them). Without it
   *  nothing can be deleted. */
  onDelete?: (entries: HistoryEntry[]) => Promise<void>;
  /** Whether an entry can be deleted (all of them by default). */
  canDelete?: (entry: HistoryEntry) => boolean;
  /** Undoes an entry's change; false if it no longer applies. Without it
   *  entries can't be reverted. */
  onRevert?: (entry: HistoryEntry) => Promise<boolean>;
  /** Shown under the list. */
  hint?: string;
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

function plural(n: number): string {
  return `${n} ${n === 1 ? "entry" : "entries"}`;
}

/** Fills `container` (a `.pm-history-list`) with the entries. */
export function renderHistoryList(
  container: HTMLElement,
  options: HistoryListOptions,
): void {
  container.replaceChildren();
  const { entries, onDelete, onRevert } = options;
  if (entries.length === 0) {
    container.append(el("p", "pm-empty-note", "No history yet."));
    if (options.hint) container.append(el("p", "pm-field-hint", options.hint));
    return;
  }

  const newestFirst = [...entries].reverse();
  const canDelete = (entry: HistoryEntry) =>
    onDelete != null && (options.canDelete?.(entry) ?? true);
  const boxes: { box: HTMLInputElement; entry: HistoryEntry }[] = [];

  const toolbar = el("div", "pm-history-toolbar");
  const allLabel = el("label", "pm-history-select-all");
  const allBox = el("input");
  allBox.type = "checkbox";
  allBox.name = "history-select-all";
  allLabel.append(allBox, document.createTextNode("Select all"));
  const deleteButton = el(
    "button",
    "pm-btn pm-btn-ghost pm-danger-text",
    "Delete selected",
  );
  deleteButton.type = "button";
  deleteButton.name = "history-delete";
  toolbar.append(allLabel, deleteButton);

  const selected = () => boxes.filter(({ box }) => box.checked);
  function updateToolbar(): void {
    const n = selected().length;
    allBox.checked = n > 0 && n === boxes.length;
    allBox.indeterminate = n > 0 && n < boxes.length;
    deleteButton.disabled = n === 0;
    deleteButton.textContent =
      n === 0 ? "Delete selected" : `Delete ${plural(n)}`;
  }

  allBox.addEventListener("change", () => {
    for (const { box } of boxes) box.checked = allBox.checked;
    updateToolbar();
  });

  deleteButton.addEventListener("click", async () => {
    const picked = selected().map(({ entry }) => entry);
    if (picked.length === 0 || onDelete == null) return;
    if (
      !window.confirm(
        `Delete ${plural(picked.length)} from the history? ${picked.length === 1 ? "That change" : "Those changes"} will stay made, but can no longer be reverted, and the values ${picked.length === 1 ? "it holds" : "they hold"} (like a password from before an edit) are gone for good.`,
      )
    )
      return;
    deleteButton.disabled = true;
    await onDelete(picked);
  });

  /** The last box clicked, from which a shift-click picks a range. */
  let anchor: number | null = null;
  const rows = newestFirst.map((entry) => {
    const row = el("div", "pm-history-entry");
    const desc = el(
      "span",
      "pm-history-desc",
      `${new Date(entry.timestamp).toLocaleString()} — ${describeHistoryEntry(entry)}`,
    );
    if (canDelete(entry)) {
      const label = el("label", "pm-history-pick");
      const box = el("input");
      box.type = "checkbox";
      const index = boxes.length;
      boxes.push({ box, entry });
      box.addEventListener("click", (event) => {
        if (event.shiftKey && anchor != null) {
          const [from, to] = [Math.min(anchor, index), Math.max(anchor, index)];
          for (let i = from; i <= to; i++) boxes[i].box.checked = box.checked;
        }
        anchor = index;
        updateToolbar();
      });
      label.append(box, desc);
      row.append(label);
    } else row.append(desc);

    if (onRevert) {
      const revertButton = el(
        "button",
        "pm-btn pm-btn-ghost pm-history-revert",
        "Revert",
      );
      revertButton.type = "button";
      revertButton.addEventListener("click", async () => {
        revertButton.disabled = true;
        if (!(await onRevert(entry)))
          revertButton.textContent = "No longer applicable";
        else revertButton.disabled = false;
      });
      row.append(revertButton);
    }
    return row;
  });

  if (boxes.length > 0) {
    container.append(toolbar);
    // lined up with the entries that have a checkbox
    for (const row of rows)
      if (row.querySelector("input") == null)
        row.classList.add("pm-history-fixed");
  }
  container.append(...rows);
  const hint =
    boxes.length > 0
      ? "Deleting entries removes them and the values they hold (like a password from before an edit) from the history; the changes themselves stay. Shift-click to select a range."
      : "";
  const hints = [hint, options.hint ?? ""].filter(Boolean).join(" ");
  if (hints) container.append(el("p", "pm-field-hint", hints));
  updateToolbar();
}
