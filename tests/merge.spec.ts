import { test, expect } from "@playwright/test";
import { mergeVaults } from "../frontend/merge";
import type { PassTableData, VaultRoot } from "../frontend/PassTable";

// Pure logic: these tests don't use the browser or the server.

function table(): PassTableData {
  return {
    id: "t1",
    name: "Logins",
    rowIds: ["r1", "r2"],
    columns: [
      { id: "site", label: "Site", type: "textarea", data: ["a.com", "b.com"] },
      {
        id: "pw",
        label: "Password",
        type: "password",
        data: [
          { type: "password", value: "pa" },
          { type: "password", value: "pb" },
        ],
      },
    ],
  };
}

function vault(): VaultRoot {
  return { tables: [table()], history: [] };
}

function col(v: VaultRoot, colId: string) {
  return v.tables[0].columns.find((c) => c.id === colId)!;
}

test.describe("mergeVaults", () => {
  test("edits to different cells merge without conflict", () => {
    const base = vault();
    const local = vault();
    col(local, "site").data[0] = "a2.com";
    const remote = vault();
    col(remote, "pw").data[1] = { type: "password", value: "pb2" };

    const { merged, conflicts } = mergeVaults(base, local, remote);
    expect(conflicts).toEqual([]);
    expect(col(merged, "site").data).toEqual(["a2.com", "b.com"]);
    expect(col(merged, "pw").data[1]).toEqual({
      type: "password",
      value: "pb2",
    });
  });

  test("the same edit on both sides is not a conflict", () => {
    const base = vault();
    const local = vault();
    const remote = vault();
    col(local, "site").data[0] = "same.com";
    col(remote, "site").data[0] = "same.com";
    const { merged, conflicts } = mergeVaults(base, local, remote);
    expect(conflicts).toEqual([]);
    expect(col(merged, "site").data[0]).toBe("same.com");
  });

  test("different edits to the same cell conflict and keep remote", () => {
    const base = vault();
    const local = vault();
    const remote = vault();
    col(local, "site").data[0] = "mine.com";
    col(remote, "site").data[0] = "theirs.com";
    const { merged, conflicts } = mergeVaults(base, local, remote);
    expect(conflicts).toHaveLength(1);
    expect(conflicts[0]).toContain('column "Site"');
    expect(col(merged, "site").data[0]).toBe("theirs.com");
  });

  test("a row added locally survives a remote cell edit", () => {
    const base = vault();
    const local = vault();
    local.tables[0].rowIds.push("r3");
    col(local, "site").data.push("c.com");
    col(local, "pw").data.push({ type: "password", value: "pc" });
    const remote = vault();
    col(remote, "site").data[0] = "a2.com";

    const { merged, conflicts } = mergeVaults(base, local, remote);
    expect(conflicts).toEqual([]);
    expect(merged.tables[0].rowIds).toEqual(["r1", "r2", "r3"]);
    expect(col(merged, "site").data).toEqual(["a2.com", "b.com", "c.com"]);
  });

  test("rows added on both sides are both kept", () => {
    const base = vault();
    const local = vault();
    local.tables[0].rowIds.push("mine");
    col(local, "site").data.push("mine.com");
    col(local, "pw").data.push({ type: "password", value: "" });
    const remote = vault();
    remote.tables[0].rowIds.push("theirs");
    col(remote, "site").data.push("theirs.com");
    col(remote, "pw").data.push({ type: "password", value: "" });

    const { merged, conflicts } = mergeVaults(base, local, remote);
    expect(conflicts).toEqual([]);
    // a local addition goes right after the row that precedes it locally
    expect(merged.tables[0].rowIds).toEqual(["r1", "r2", "mine", "theirs"]);
    expect(col(merged, "site").data).toEqual([
      "a.com",
      "b.com",
      "mine.com",
      "theirs.com",
    ]);
  });

  test("an unchanged row deleted remotely stays deleted", () => {
    const base = vault();
    const local = vault();
    col(local, "site").data[1] = "b2.com";
    const remote = vault();
    remote.tables[0].rowIds.splice(0, 1);
    remote.tables[0].columns.forEach((c) => c.data.splice(0, 1));

    const { merged, conflicts } = mergeVaults(base, local, remote);
    expect(conflicts).toEqual([]);
    expect(merged.tables[0].rowIds).toEqual(["r2"]);
    expect(col(merged, "site").data).toEqual(["b2.com"]);
  });

  test("deleting a row the other session edited conflicts and keeps remote", () => {
    const base = vault();
    const local = vault();
    local.tables[0].rowIds.splice(0, 1);
    local.tables[0].columns.forEach((c) => c.data.splice(0, 1));
    const remote = vault();
    col(remote, "site").data[0] = "a2.com";

    const { merged, conflicts } = mergeVaults(base, local, remote);
    expect(conflicts).toHaveLength(1);
    expect(conflicts[0]).toContain("deleted here");
    expect(merged.tables[0].rowIds).toEqual(["r1", "r2"]);
    expect(col(merged, "site").data[0]).toBe("a2.com");
  });

  test("a column deleted locally stays deleted if remote only added rows", () => {
    const base = vault();
    const local = vault();
    local.tables[0].columns.splice(1, 1); // delete "pw"
    const remote = vault();
    remote.tables[0].rowIds.push("r3");
    col(remote, "site").data.push("c.com");
    col(remote, "pw").data.push({ type: "password", value: "" });

    const { merged, conflicts } = mergeVaults(base, local, remote);
    expect(conflicts).toEqual([]);
    expect(merged.tables[0].columns.map((c) => c.id)).toEqual(["site"]);
    expect(col(merged, "site").data).toEqual(["a.com", "b.com", "c.com"]);
  });

  test("a column added locally gets default cells for remote's new rows", () => {
    const base = vault();
    const local = vault();
    local.tables[0].columns.push({
      id: "notes",
      label: "Notes",
      type: "textarea",
      data: ["n1", "n2"],
    });
    const remote = vault();
    remote.tables[0].rowIds.push("r3");
    col(remote, "site").data.push("c.com");
    col(remote, "pw").data.push({ type: "password", value: "" });

    const { merged, conflicts } = mergeVaults(base, local, remote);
    expect(conflicts).toEqual([]);
    expect(col(merged, "notes").data).toEqual(["n1", "n2", ""]);
  });

  test("an addition with no neighbour on its side goes at the end", () => {
    const empty: VaultRoot = { tables: [], history: [] };
    const local: VaultRoot = {
      tables: [{ id: "mine", name: "Mine", rowIds: [], columns: [] }],
      history: [],
    };
    const remote: VaultRoot = {
      tables: [{ id: "theirs", name: "Theirs", rowIds: [], columns: [] }],
      history: [],
    };
    const { merged } = mergeVaults(empty, local, remote);
    expect(merged.tables.map((t) => t.id)).toEqual(["theirs", "mine"]);
  });

  test("tables added on either side and renames merge", () => {
    const base = vault();
    const local = vault();
    local.tables.push({ id: "t2", name: "Wifi", rowIds: [], columns: [] });
    const remote = vault();
    remote.tables[0].name = "Websites";

    const { merged, conflicts } = mergeVaults(base, local, remote);
    expect(conflicts).toEqual([]);
    expect(merged.tables.map((t) => t.name)).toEqual(["Websites", "Wifi"]);
  });

  test("history from both sessions is combined in time order", () => {
    const base = vault();
    const entry = (timestamp: string, newName: string) => ({
      kind: "table-name" as const,
      timestamp,
      tableId: "t1",
      previousName: "Logins",
      newName,
    });
    base.history = [entry("2026-01-01T00:00:00Z", "a")];
    const local = structuredClone(base);
    local.history.push(entry("2026-01-03T00:00:00Z", "local"));
    const remote = structuredClone(base);
    remote.history.push(entry("2026-01-02T00:00:00Z", "remote"));

    const { merged } = mergeVaults(base, local, remote);
    expect(
      merged.history.map((h) => (h.kind === "table-name" ? h.newName : "")),
    ).toEqual(["a", "remote", "local"]);
  });

  test("the merged vault shares no objects with its inputs", () => {
    const base = vault();
    const local = vault();
    const remote = vault();
    col(local, "site").data[0] = "a2.com";
    const { merged } = mergeVaults(base, local, remote);
    col(merged, "pw").data[0] = { type: "password", value: "changed" };
    merged.tables[0].rowIds.push("x");
    expect(col(remote, "pw").data[0]).toEqual({
      type: "password",
      value: "pa",
    });
    expect(remote.tables[0].rowIds).toEqual(["r1", "r2"]);
  });
});
