// Three-way merge of a vault, used when a save is refused because another
// session saved first. The server only sees ciphertext, so merging happens
// here: `base` is the version this session last loaded or saved, `local` is
// this session's current data and `remote` is the newer version on the server.
// Tables, columns and rows are matched by id and cells by (row id, column id),
// so a change on one side merges cleanly with an unrelated change on the
// other. A conflict is the same item changed differently on both sides, or
// deleted on one side and changed on the other; it resolves to `remote`.

import type {
  CellValue,
  HistoryEntry,
  LinkCellData,
  PassTableColumn,
  PassTableData,
  PasswordCellData,
  VaultRoot,
} from "./PassTable";

export interface MergeResult {
  /** The merged vault; conflicts are resolved in favour of `remote`. */
  merged: VaultRoot;
  /** One description per conflict; empty when the merge was clean. */
  conflicts: string[];
}

const HISTORY_LIMIT = 100;

/** JSON with object keys sorted, so equal values always compare equal. */
function canonical(value: unknown): string {
  return JSON.stringify(value, (_key, v: unknown) =>
    v != null && typeof v === "object" && !Array.isArray(v)
      ? Object.fromEntries(
          Object.entries(v).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
        )
      : v,
  );
}

function same(a: unknown, b: unknown): boolean {
  return canonical(a) === canonical(b);
}

export function vaultsEqual(a: VaultRoot, b: VaultRoot): boolean {
  return same(a, b);
}

/** Merges one value; `undefined` means absent on that side. */
function merge3<T>(
  base: T | undefined,
  local: T | undefined,
  remote: T | undefined,
): { value: T | undefined; conflict: boolean } {
  if (same(local, remote)) return { value: local, conflict: false };
  if (same(local, base)) return { value: remote, conflict: false };
  if (same(remote, base)) return { value: local, conflict: false };
  return { value: remote, conflict: true };
}

function defaultCell(type: PassTableColumn["type"]): CellValue {
  if (type === "textarea") return "";
  if (type === "link") return { url: "" };
  return { type: "password", value: "" };
}

function makeColumn(
  id: string,
  label: string,
  type: PassTableColumn["type"],
  data: CellValue[],
): PassTableColumn {
  if (type === "textarea") return { id, label, type, data: data as string[] };
  if (type === "link") return { id, label, type, data: data as LinkCellData[] };
  return { id, label, type, data: data as PasswordCellData[] };
}

/** Index of a table's rows and columns by id. */
class TableView {
  private readonly rowIndex: Map<string, number>;
  readonly cols: Map<string, PassTableColumn>;

  constructor(readonly table: PassTableData) {
    this.rowIndex = new Map(table.rowIds.map((id, i) => [id, i]));
    this.cols = new Map(table.columns.map((c) => [c.id, c]));
  }

  hasRow(rowId: string): boolean {
    return this.rowIndex.has(rowId);
  }

  cell(rowId: string, colId: string): CellValue | undefined {
    const row = this.rowIndex.get(rowId);
    const col = this.cols.get(colId);
    return row === undefined || col === undefined ? undefined : col.data[row];
  }

  /** Whether `side` changed any cell of this row compared with `base`. */
  static rowChanged(
    side: TableView,
    base: TableView | undefined,
    rowId: string,
  ): boolean {
    for (const col of side.cols.values()) {
      const before = base?.cell(rowId, col.id) ?? defaultCell(col.type);
      if (!same(side.cell(rowId, col.id), before)) return true;
    }
    return false;
  }

  /** Whether `side` renamed this column or changed any of its cells. */
  static colChanged(
    side: TableView,
    base: TableView | undefined,
    colId: string,
  ): boolean {
    const col = side.cols.get(colId)!;
    const baseCol = base?.cols.get(colId);
    if (baseCol && (baseCol.label !== col.label || baseCol.type !== col.type))
      return true;
    return side.table.rowIds.some((rowId) => {
      const before = base?.cell(rowId, colId) ?? defaultCell(col.type);
      return !same(side.cell(rowId, colId), before);
    });
  }
}

/** Remote's order, with each item only `local` has placed next to its local
 *  neighbour: after the nearest item before it, else before the nearest item
 *  after it, else at the end. */
function mergeOrder(
  localIds: string[],
  remoteIds: string[],
  kept: Set<string>,
): string[] {
  const result = remoteIds.filter((id) => kept.has(id));
  localIds.forEach((id, i) => {
    if (!kept.has(id) || result.includes(id)) return;
    const before = localIds
      .slice(0, i)
      .reverse()
      .find((other) => result.includes(other));
    const after = localIds.slice(i + 1).find((other) => result.includes(other));
    const at =
      before !== undefined
        ? result.indexOf(before) + 1
        : after !== undefined
          ? result.indexOf(after)
          : result.length;
    result.splice(at, 0, id);
  });
  for (const id of kept) if (!result.includes(id)) result.push(id);
  return result;
}

/**
 * Decides which of the ids seen on either side survive. An id deleted on one
 * side survives only if the other side changed it (a conflict, which keeps the
 * remote version).
 */
function keptIds(
  baseIds: Set<string>,
  localIds: Set<string>,
  remoteIds: Set<string>,
  changedLocally: (id: string) => boolean,
  changedRemotely: (id: string) => boolean,
  onConflict: (id: string, deletedLocally: boolean) => void,
): Set<string> {
  const kept = new Set<string>();
  for (const id of new Set([...localIds, ...remoteIds])) {
    const inLocal = localIds.has(id);
    const inRemote = remoteIds.has(id);
    if (inLocal && inRemote) {
      kept.add(id);
    } else if (!baseIds.has(id)) {
      kept.add(id); // added on one side
    } else if (inLocal) {
      // deleted remotely
      if (changedLocally(id)) onConflict(id, false);
    } else if (changedRemotely(id)) {
      // deleted locally, changed remotely: keep the remote version
      onConflict(id, true);
      kept.add(id);
    }
  }
  return kept;
}

function mergeTable(
  base: PassTableData | undefined,
  local: PassTableData | undefined,
  remote: PassTableData | undefined,
  conflicts: string[],
): PassTableData {
  // a table present on only one side is taken as is
  if (!local || !remote) return structuredClone((local ?? remote)!);

  const b = base && new TableView(base);
  const l = new TableView(local);
  const r = new TableView(remote);
  const where = `Table "${remote.name}"`;

  const name = merge3(base?.name, local.name, remote.name);
  if (name.conflict)
    conflicts.push(`${where}: renamed differently in both sessions`);

  const keptCols = keptIds(
    new Set(b?.cols.keys()),
    new Set(l.cols.keys()),
    new Set(r.cols.keys()),
    (id) => TableView.colChanged(l, b, id),
    (id) => TableView.colChanged(r, b, id),
    (id, deletedLocally) => {
      const label = (r.cols.get(id) ?? l.cols.get(id))!.label;
      conflicts.push(
        deletedLocally
          ? `${where}: column "${label}" was deleted here but changed in the other session`
          : `${where}: column "${label}" was changed here but deleted in the other session`,
      );
    },
  );
  const keptRows = keptIds(
    new Set(base?.rowIds),
    new Set(local.rowIds),
    new Set(remote.rowIds),
    (id) => TableView.rowChanged(l, b, id),
    (id) => TableView.rowChanged(r, b, id),
    (id, deletedLocally) => {
      const n = (r.hasRow(id) ? remote : local).rowIds.indexOf(id) + 1;
      conflicts.push(
        deletedLocally
          ? `${where}: row ${n} was deleted here but changed in the other session`
          : `${where}: row ${n} was changed here but deleted in the other session`,
      );
    },
  );

  const colIds = mergeOrder(
    local.columns.map((c) => c.id),
    remote.columns.map((c) => c.id),
    keptCols,
  );
  const rowIds = mergeOrder(local.rowIds, remote.rowIds, keptRows);

  const columns = colIds.map((colId) => {
    const bc = b?.cols.get(colId);
    const lc = l.cols.get(colId);
    const rc = r.cols.get(colId);
    // a column on only one side was added there (or deleted on the other and
    // kept by a conflict), so its label is taken as is
    const label =
      lc && rc
        ? merge3(bc?.label, lc.label, rc.label)
        : { value: (rc ?? lc)!.label, conflict: false };
    if (label.conflict)
      conflicts.push(
        `${where}: column "${rc!.label}" was renamed differently in both sessions`,
      );
    const type = (rc ?? lc)!.type;
    const data = rowIds.map((rowId, i) => {
      const lv = lc && l.cell(rowId, colId);
      const rv = rc && r.cell(rowId, colId);
      if (lv === undefined && rv === undefined) return defaultCell(type);
      if (lv === undefined) return rv!;
      if (rv === undefined) return lv;
      const cell = merge3(b?.cell(rowId, colId), lv, rv);
      if (cell.conflict)
        conflicts.push(
          `${where}, row ${i + 1}, column "${rc!.label}": changed differently in both sessions`,
        );
      return cell.value!;
    });
    return makeColumn(colId, label.value!, type, structuredClone(data));
  });

  return { id: remote.id, name: name.value!, rowIds, columns };
}

/** Union of both sides' history (entries new since `base`), oldest first. */
function mergeHistory(
  base: HistoryEntry[],
  local: HistoryEntry[],
  remote: HistoryEntry[],
): HistoryEntry[] {
  const known = new Set([...base, ...remote].map(canonical));
  const merged = [
    ...remote,
    ...local.filter((entry) => !known.has(canonical(entry))),
  ];
  merged.sort((a, b) =>
    a.timestamp < b.timestamp ? -1 : a.timestamp > b.timestamp ? 1 : 0,
  );
  return structuredClone(merged.slice(-HISTORY_LIMIT));
}

export function mergeVaults(
  base: VaultRoot,
  local: VaultRoot,
  remote: VaultRoot,
): MergeResult {
  const conflicts: string[] = [];
  const byId = (v: VaultRoot) => new Map(v.tables.map((t) => [t.id, t]));
  const b = byId(base);
  const l = byId(local);
  const r = byId(remote);

  const kept = keptIds(
    new Set(b.keys()),
    new Set(l.keys()),
    new Set(r.keys()),
    (id) => !same(l.get(id), b.get(id)),
    (id) => !same(r.get(id), b.get(id)),
    (id, deletedLocally) => {
      const name = (r.get(id) ?? l.get(id))!.name;
      conflicts.push(
        deletedLocally
          ? `Table "${name}" was deleted here but changed in the other session`
          : `Table "${name}" was changed here but deleted in the other session`,
      );
    },
  );
  const tables = mergeOrder(
    local.tables.map((t) => t.id),
    remote.tables.map((t) => t.id),
    kept,
  ).map((id) => mergeTable(b.get(id), l.get(id), r.get(id), conflicts));

  const merged: VaultRoot = {
    tables,
    history: mergeHistory(base.history, local.history, remote.history),
  };
  const sharingKeys = merge3(
    base.sharingKeys,
    local.sharingKeys,
    remote.sharingKeys,
  );
  if (sharingKeys.conflict)
    conflicts.push("Sharing was set up in both sessions");
  if (sharingKeys.value != null)
    merged.sharingKeys = structuredClone(sharingKeys.value);

  return { merged, conflicts };
}
