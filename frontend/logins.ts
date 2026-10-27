// Logins in a vault's tables, as the browser extensions and the Android app's
// autofill see them. Tables are free-form, so a row is a login when it has a
// link (the site) and a username, password or MFA key; which column holds the
// username is told by its label, as for CSV imports (vaultTransfer.ts).
//
// Logins for Android apps link to "android://<hash>@<package name>/" (the
// form Google's password manager uses), where the hash is the base64url
// SHA-256 of the app's signing certificate: another app can take the package
// name, but can't be signed with that certificate.

import type {
  CellValue,
  HistoryEntry,
  PassTableColumn,
  PassTableData,
  VaultRoot,
} from "./PassTable";
import { getDefaultCellValue } from "./PassTable";

export interface Login {
  /** Where it comes from: the user's own vault, or a shared vault. */
  source: { kind: "own" } | { kind: "shared"; vaultId: string; name: string };
  tableId: string;
  rowId: string;
  name: string;
  urls: string[];
  username: string;
  password: string;
  /** The Base32 MFA key, for one-time codes. */
  mfaKey: string;
}

const normalize = (label: string) =>
  label.toLowerCase().replace(/[^a-z0-9]/g, "");

const USERNAME_LABELS = [
  "username",
  "user",
  "login",
  "loginname",
  "email",
  "emailaddress",
  "userid",
  "account",
];
const NAME_LABELS = ["name", "title", "sitename"];
const MFA_LABEL = /mfa|totp|otp|2fa|authenticator/;

function usernameColumn(table: PassTableData) {
  const text = table.columns.filter((c) => c.type === "textarea");
  return (
    text.find((c) => USERNAME_LABELS.includes(normalize(c.label))) ??
    text.find((c) => /user|email|login/.test(normalize(c.label)))
  );
}

function nameColumn(table: PassTableData) {
  return table.columns.find(
    (c) => c.type === "textarea" && NAME_LABELS.includes(normalize(c.label)),
  );
}

/** The column new passwords go in (not one holding MFA keys). */
function passwordColumn(table: PassTableData) {
  const columns = table.columns.filter(
    (c) =>
      c.type === "password" &&
      !MFA_LABEL.test(normalize(c.label)) &&
      !c.data.some((cell) => cell.type === "mfa-key"),
  );
  return columns.find((c) => /pass/.test(normalize(c.label))) ?? columns[0];
}

/** Every login in `tables`. */
export function loginsIn(
  tables: PassTableData[],
  source: Login["source"],
): Login[] {
  const logins: Login[] = [];
  for (const table of tables) {
    const userCol = usernameColumn(table);
    const nameCol = nameColumn(table);
    table.rowIds.forEach((rowId, row) => {
      const urls: string[] = [];
      let linkText = "";
      let password = "";
      let mfaKey = "";
      for (const column of table.columns) {
        if (column.type === "link") {
          const link = column.data[row];
          if (link?.url) {
            urls.push(link.url);
            linkText ||= link.text ?? "";
          }
        } else if (column.type === "password") {
          const cell = column.data[row];
          if (cell == null || cell.value === "") continue;
          if (cell.type === "mfa-key") mfaKey ||= cell.value;
          else password ||= cell.value;
        }
      }
      const username =
        userCol?.type === "textarea" ? (userCol.data[row] ?? "").trim() : "";
      if (urls.length === 0 && !password && !username && !mfaKey) return;
      const named =
        nameCol?.type === "textarea" ? (nameCol.data[row] ?? "").trim() : "";
      logins.push({
        source,
        tableId: table.id,
        rowId,
        name: named || linkText || hostOf(urls[0] ?? "") || table.name,
        urls,
        username,
        password,
        mfaKey,
      });
    });
  }
  return logins;
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

/** URLs saved without a scheme ("example.com") are taken as https. */
function parseSaved(url: string): URL | null {
  const text = url.trim();
  try {
    return new URL(
      /^[a-z][a-z0-9+.-]*:/i.test(text) ? text : `https://${text}`,
    );
  } catch {
    return null;
  }
}

/**
 * Whether a login saved for `saved` may be filled on a page at `page`: the
 * same host or a subdomain of it ("example.com" covers
 * "login.example.com"), the same port if the saved one names a port, and
 * never from https into an http page.
 */
export function urlMatches(saved: string, page: URL): boolean {
  const url = parseSaved(saved);
  if (url == null) return false;
  if (url.protocol !== "https:" && url.protocol !== "http:") return false;
  if (page.protocol !== "https:" && page.protocol !== "http:") return false;
  if (url.protocol === "https:" && page.protocol === "http:") return false;
  if (url.port !== "" && url.port !== page.port) return false;
  const host = url.hostname.replace(/^www\./, "");
  return page.hostname === host || page.hostname.endsWith(`.${host}`);
}

/** Whether every one of `terms` (see vaultSearch.ts) is in the login's
 *  name, username or links. */
export function loginHasTerms(login: Login, terms: string[]): boolean {
  const text = [login.name, login.username, ...login.urls]
    .join("\n")
    .normalize("NFKD")
    .replace(/\p{M}/gu, "")
    .toLocaleLowerCase();
  return terms.every((term) => text.includes(term));
}

export function loginMatches(login: Login, page: URL): boolean {
  return login.urls.some((url) => urlMatches(url, page));
}

/** An Android app, as Android identifies it. */
export interface AndroidApp {
  packageName: string;
  /** The base64url (with padding) SHA-256 of its signing certificate. */
  certHash: string;
}

/** The link saved for logins to `app`. */
export function appLink(app: AndroidApp): string {
  return `android://${app.certHash}@${app.packageName}/`;
}

/** Whether a login saved for `saved` is for `app`. (Parsed by hand: older
 *  browsers' URL parsers, Android's web view among them, don't split
 *  "android://…" into a user name and host.) */
export function appMatches(saved: string, app: AndroidApp): boolean {
  const match = /^android:\/\/([^@/?#]+)@([^/?#]+)\/?$/i.exec(saved.trim());
  if (match == null) return false;
  let certHash: string;
  try {
    certHash = decodeURIComponent(match[1]);
  } catch {
    return false;
  }
  return match[2] === app.packageName && certHash === app.certHash;
}

/** Where a login is saved for: a web page or an app. */
export interface Site {
  /** What goes in the link column. */
  link: string;
  /** The name for a new login. */
  name: string;
  /** Whether `login` is for this site. */
  matches(login: Login): boolean;
}

export function webSite(page: URL): Site {
  return {
    link: page.origin,
    name: page.hostname.replace(/^www\./, ""),
    matches: (login) => loginMatches(login, page),
  };
}

export function appSite(app: AndroidApp, label: string): Site {
  return {
    link: appLink(app),
    name: label,
    matches: (login) => login.urls.some((url) => appMatches(url, app)),
  };
}

/** Tables a new login can go in: those with a link and a password column. */
export function loginTables(vault: VaultRoot): PassTableData[] {
  return vault.tables.filter(
    (t) =>
      t.columns.some((c) => c.type === "link") && passwordColumn(t) != null,
  );
}

export const NEW_TABLE = "new";

/**
 * Saves a login in the user's own vault: changes the password of the login
 * for `site` with this username if there is one, else adds a row to the
 * table `tableId` (or to a new "Logins" table if it's `NEW_TABLE`), adding
 * any column it lacks. Changes `vault` and returns the history entries.
 */
export function saveLogin(
  vault: VaultRoot,
  login: { site: Site; username: string; password: string },
  tableId: string,
): { entries: HistoryEntry[]; updated: boolean } {
  const timestamp = new Date().toISOString();
  const entries: HistoryEntry[] = [];
  const cellEdit = (
    table: PassTableData,
    column: PassTableColumn,
    row: number,
    previousValue: CellValue,
    newValue: CellValue,
  ) =>
    entries.push({
      kind: "cell-edit",
      timestamp,
      tableId: table.id,
      tableName: table.name,
      colId: column.id,
      colLabel: column.label,
      rowId: table.rowIds[row],
      rowIndex: row,
      previousValue,
      newValue,
    });

  const existing = loginsIn(vault.tables, { kind: "own" }).find(
    (l) =>
      l.username === login.username &&
      login.site.matches(l) &&
      l.password !== "",
  );
  if (existing) {
    const table = vault.tables.find((t) => t.id === existing.tableId)!;
    const row = table.rowIds.indexOf(existing.rowId);
    // the column the password was read from
    const column = table.columns.find(
      (c) =>
        c.type === "password" &&
        c.data[row]?.type === "password" &&
        c.data[row].value === existing.password,
    );
    if (column?.type === "password") {
      const previous = column.data[row];
      const next = { type: "password" as const, value: login.password };
      column.data[row] = next;
      cellEdit(table, column, row, previous, next);
      pushHistory(vault, entries);
      return { entries, updated: true };
    }
  }

  let table = vault.tables.find((t) => t.id === tableId);
  if (table == null) {
    table = {
      id: crypto.randomUUID(),
      rowIds: [],
      name: uniqueName(vault, "Logins"),
      columns: [],
    };
    vault.tables.push(table);
    entries.push({
      kind: "table-add",
      timestamp,
      tableId: table.id,
      tableName: table.name,
    });
  }
  const target = table;
  const ensure = (
    found: PassTableColumn | undefined,
    label: string,
    type: PassTableColumn["type"],
  ): PassTableColumn => {
    if (found) return found;
    const column = {
      id: crypto.randomUUID(),
      label,
      type,
      data: target.rowIds.map(() => getDefaultCellValue(type)),
    } as PassTableColumn;
    target.columns.push(column);
    entries.push({
      kind: "col-add",
      timestamp,
      tableId: target.id,
      tableName: target.name,
      colId: column.id,
      colLabel: column.label,
    });
    return column;
  };
  const siteCol = ensure(
    target.columns.find((c) => c.type === "link"),
    "Site",
    "link",
  );
  const userCol = ensure(usernameColumn(target), "Username", "textarea");
  const passCol = ensure(passwordColumn(target), "Password", "password");

  const rowId = crypto.randomUUID();
  target.rowIds.push(rowId);
  for (const column of target.columns) {
    const value = getDefaultCellValue(column.type);
    if (column.type === "textarea") column.data.push(value as string);
    else if (column.type === "link") column.data.push(value as { url: string });
    else column.data.push(value as { type: "password"; value: string });
  }
  const row = target.rowIds.length - 1;
  entries.push({
    kind: "row-add",
    timestamp,
    tableId: target.id,
    tableName: target.name,
    rowId,
    rowIndex: row,
  });
  const set = (column: PassTableColumn, value: CellValue) => {
    const previous = column.data[row];
    if (column.type === "textarea") column.data[row] = value as string;
    else if (column.type === "link")
      column.data[row] = value as { url: string };
    else column.data[row] = value as { type: "password"; value: string };
    cellEdit(target, column, row, previous, value);
  };
  set(siteCol, { url: login.site.link });
  const nameCol = nameColumn(target);
  if (nameCol) set(nameCol, login.site.name);
  if (login.username) set(userCol, login.username);
  set(passCol, { type: "password", value: login.password });
  pushHistory(vault, entries);
  return { entries, updated: false };
}

function uniqueName(vault: VaultRoot, base: string): string {
  const names = new Set(vault.tables.map((t) => t.name));
  let name = base;
  for (let i = 2; names.has(name); i++) name = `${base} ${i}`;
  return name;
}

/** Keeps the last 100 entries, as the web app does. */
function pushHistory(vault: VaultRoot, entries: HistoryEntry[]): void {
  vault.history.push(...entries);
  if (vault.history.length > 100)
    vault.history.splice(0, vault.history.length - 100);
}

/**
 * Adds `link` to the row of `login` (from the user's own vault): in its first
 * empty link cell, or in a new "App" link column. Changes `vault` and returns
 * the history entries, or null if the login is no longer there.
 */
export function addLink(
  vault: VaultRoot,
  login: Login,
  link: string,
): HistoryEntry[] | null {
  const table = vault.tables.find((t) => t.id === login.tableId);
  const row = table?.rowIds.indexOf(login.rowId) ?? -1;
  if (table == null || row < 0) return null;
  const timestamp = new Date().toISOString();
  const entries: HistoryEntry[] = [];
  let column = table.columns.find(
    (c) => c.type === "link" && !c.data[row]?.url,
  );
  if (column == null) {
    column = {
      id: crypto.randomUUID(),
      label: "App",
      type: "link",
      data: table.rowIds.map(() => ({ url: "" })),
    };
    table.columns.push(column);
    entries.push({
      kind: "col-add",
      timestamp,
      tableId: table.id,
      tableName: table.name,
      colId: column.id,
      colLabel: column.label,
    });
  }
  if (column.type !== "link") return null;
  const previousValue = column.data[row];
  const newValue = { url: link };
  column.data[row] = newValue;
  entries.push({
    kind: "cell-edit",
    timestamp,
    tableId: table.id,
    tableName: table.name,
    colId: column.id,
    colLabel: column.label,
    rowId: login.rowId,
    rowIndex: row,
    previousValue,
    newValue,
  });
  pushHistory(vault, entries);
  return entries;
}
