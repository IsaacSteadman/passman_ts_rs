// Moving tables in and out of the vault: encrypted backups, unencrypted
// exports, and CSV files from other password managers. Imported files are
// untrusted, so their contents are checked before they reach the vault.

import type {
  LinkCellData,
  PassTableColumn,
  PassTableData,
  PasswordCellData,
} from "./PassTable";
import {
  SALT_LEN,
  decryptBlob,
  deriveKey,
  encryptBlob,
} from "./passman_crypto_glue";

const EXPORT_FORMAT = "passman-export";
const BACKUP_FORMAT = "passman-backup";

/** Files larger than this aren't read. */
export const MAX_IMPORT_BYTES = 20 * 1024 * 1024;

// ── Exports and backups ──────────────────────────────────────────────────────

interface ExportDocument {
  format: typeof EXPORT_FORMAT;
  version: 1;
  exported: string;
  tables: PassTableData[];
}

/** Version 1: the key is Argon2id (the app's parameters) of the password
 *  with `salt`; `data` is an XChaCha20-Poly1305 blob of an export document. */
interface BackupFile {
  format: typeof BACKUP_FORMAT;
  version: 1;
  salt: string;
  data: string;
}

/** Only the tables: the history holds earlier and deleted values. */
export function exportTables(tables: PassTableData[]): string {
  const doc: ExportDocument = {
    format: EXPORT_FORMAT,
    version: 1,
    exported: new Date().toISOString(),
    tables,
  };
  return JSON.stringify(doc, null, 2);
}

export function encryptBackup(
  tables: PassTableData[],
  password: string,
): string {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const data = encryptBlob(
    deriveKey(password, salt),
    new TextEncoder().encode(exportTables(tables)),
  );
  const backup: BackupFile = {
    format: BACKUP_FORMAT,
    version: 1,
    salt: toBase64(salt),
    data: toBase64(data),
  };
  return JSON.stringify(backup);
}

export class ImportError extends Error {}

/** A file read for importing: tables ready to add, or a backup that needs
 *  its password first. */
export type ImportSource =
  | { kind: "tables"; tables: PassTableData[]; warnings: string[] }
  | { kind: "backup"; unlock(password: string): PassTableData[] };

export async function readImportFile(file: File): Promise<ImportSource> {
  if (file.size > MAX_IMPORT_BYTES)
    throw new ImportError("The file is too large to import (over 20 MB).");
  const text = await file.text();
  if (/^﻿?\s*\{/.test(text)) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new ImportError("The file isn't valid JSON.");
    }
    return fromJson(parsed);
  }
  return { kind: "tables", ...tablesFromCsv(text, file.name) };
}

function fromJson(parsed: unknown): ImportSource {
  if (!isRecord(parsed))
    throw new ImportError("This isn't a Passman export or backup.");
  if (parsed.format === BACKUP_FORMAT) {
    if (
      parsed.version !== 1 ||
      typeof parsed.salt !== "string" ||
      typeof parsed.data !== "string"
    )
      throw new ImportError(
        "This backup was made by a newer version of Passman, or is damaged.",
      );
    const salt = fromBase64(parsed.salt);
    const data = fromBase64(parsed.data);
    if (salt.byteLength !== SALT_LEN)
      throw new ImportError("This backup is damaged.");
    return {
      kind: "backup",
      unlock(password) {
        let plaintext: Uint8Array;
        try {
          plaintext = decryptBlob(deriveKey(password, salt), data);
        } catch {
          throw new ImportError("Wrong backup password, or a damaged backup.");
        }
        const source = fromJson(
          JSON.parse(new TextDecoder().decode(plaintext)),
        );
        if (source.kind !== "tables")
          throw new ImportError("This backup is damaged.");
        return source.tables;
      },
    };
  }
  if (parsed.format === EXPORT_FORMAT) {
    if (parsed.version !== 1 || !Array.isArray(parsed.tables))
      throw new ImportError(
        "This export was made by a newer version of Passman, or is damaged.",
      );
    return {
      kind: "tables",
      tables: parsed.tables.map(parseTable),
      warnings: [],
    };
  }
  throw new ImportError("This isn't a Passman export or backup.");
}

/** Checks a table from a file; ids are replaced when importing. */
function parseTable(value: unknown, index: number): PassTableData {
  const where = `Table ${index + 1}`;
  if (!isRecord(value) || typeof value.name !== "string")
    throw new ImportError(`${where} has no name.`);
  if (!Array.isArray(value.columns))
    throw new ImportError(`${where} has no columns.`);
  const columns = value.columns.map((column, c): PassTableColumn => {
    const at = `${where}, column ${c + 1}`;
    if (
      !isRecord(column) ||
      typeof column.label !== "string" ||
      !Array.isArray(column.data)
    )
      throw new ImportError(`${at} is damaged.`);
    const { label, data } = column;
    switch (column.type) {
      case "textarea":
        if (!data.every((cell) => typeof cell === "string"))
          throw new ImportError(`${at} has a value that isn't text.`);
        return { id: "", label, type: "textarea", data };
      case "link":
        return { id: "", label, type: "link", data: data.map(parseLink(at)) };
      case "password":
        return {
          id: "",
          label,
          type: "password",
          data: data.map(parsePassword(at)),
        };
      default:
        throw new ImportError(`${at} has an unknown type.`);
    }
  });
  const rows = columns[0]?.data.length ?? 0;
  if (columns.some((column) => column.data.length !== rows))
    throw new ImportError(`${where} has columns of different lengths.`);
  return {
    id: "",
    name: value.name,
    rowIds: Array.from({ length: rows }, () => ""),
    columns,
  };
}

const parseLink =
  (at: string) =>
  (cell: unknown): LinkCellData => {
    if (
      !isRecord(cell) ||
      typeof cell.url !== "string" ||
      (cell.text !== undefined && typeof cell.text !== "string")
    )
      throw new ImportError(`${at} has a damaged link.`);
    return cell.text === undefined
      ? { url: cell.url }
      : { url: cell.url, text: cell.text };
  };

const parsePassword =
  (at: string) =>
  (cell: unknown): PasswordCellData => {
    if (
      !isRecord(cell) ||
      (cell.type !== "password" && cell.type !== "mfa-key") ||
      typeof cell.value !== "string"
    )
      throw new ImportError(`${at} has a damaged password.`);
    return { type: cell.type, value: cell.value };
  };

/** Gives the tables new ids (so they never clash with the vault's) and
 *  names that aren't already used. */
export function prepareForVault(
  tables: PassTableData[],
  existingNames: string[],
): PassTableData[] {
  const used = new Set(existingNames);
  return tables.map((table) => {
    let name = table.name;
    for (let n = 1; used.has(name); n++)
      name = `${table.name} (imported${n > 1 ? ` ${n}` : ""})`;
    used.add(name);
    return {
      id: crypto.randomUUID(),
      name,
      rowIds: table.rowIds.map(() => crypto.randomUUID()),
      columns: table.columns.map((column) => ({
        ...structuredClone(column),
        id: crypto.randomUUID(),
      })),
    };
  });
}

// ── CSV from other password managers ─────────────────────────────────────────

/** Parses CSV (RFC 4180: quoted fields may hold commas, quotes and line
 *  breaks). */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  let i = text.charCodeAt(0) === 0xfeff ? 1 : 0;
  for (; i < text.length; i++) {
    const char = text[i];
    if (quoted) {
      if (char !== '"') field += char;
      else if (text[i + 1] === '"') {
        field += '"';
        i++;
      } else quoted = false;
    } else if (char === '"') quoted = true;
    else if (char === ",") {
      row.push(field);
      field = "";
    } else if (char === "\n" || char === "\r") {
      if (char === "\r" && text[i + 1] === "\n") i++;
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else field += char;
  }
  if (field !== "" || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows.filter((r) => r.some((value) => value.trim() !== ""));
}

type Role = "name" | "url" | "username" | "password" | "totp" | "notes";

/** Header names used by Bitwarden, 1Password, Chrome, Firefox and Safari,
 *  lower case without punctuation. */
const ROLE_HEADERS: Record<Role, string[]> = {
  name: ["name", "title"],
  url: ["url", "loginuri", "uri", "website", "site"],
  username: ["username", "loginusername", "user", "login"],
  password: ["password", "loginpassword"],
  totp: ["totp", "logintotp", "otpauth", "otp"],
  notes: ["notes", "note", "extra", "comments"],
};
const ROLE_COLUMNS: { role: Role; label: string }[] = [
  { role: "name", label: "Name" },
  { role: "url", label: "Site" },
  { role: "username", label: "Username" },
  { role: "password", label: "Password" },
  { role: "totp", label: "MFA Key" },
  { role: "notes", label: "Notes" },
];
/** Bookkeeping columns with nothing worth keeping. */
const SKIPPED_HEADERS = new Set([
  "type",
  "guid",
  "httprealm",
  "formactionorigin",
  "timecreated",
  "timelastused",
  "timepasswordchanged",
  "reprompt",
  "favorite",
  "archived",
]);

const normalizeHeader = (header: string) =>
  header.toLowerCase().replace(/[^a-z0-9]/g, "");

export function tablesFromCsv(
  text: string,
  fileName: string,
): { tables: PassTableData[]; warnings: string[] } {
  const [header, ...rows] = parseCsv(text);
  if (header == null || rows.length === 0)
    throw new ImportError("The file has no entries to import.");

  // which file column fills each role; the rest are kept as text columns
  const roleIndex = new Map<Role, number>();
  const extraIndexes: number[] = [];
  header.forEach((title, index) => {
    const key = normalizeHeader(title);
    const role = (Object.keys(ROLE_HEADERS) as Role[]).find((r) =>
      ROLE_HEADERS[r].includes(key),
    );
    if (role != null && !roleIndex.has(role)) roleIndex.set(role, index);
    else if (!SKIPPED_HEADERS.has(key) && key !== "") extraIndexes.push(index);
  });
  if (!roleIndex.has("password") && !roleIndex.has("username"))
    throw new ImportError(
      "No username or password column found. Is this a password export?",
    );

  const warnings: string[] = [];
  let unsupportedMfa = 0;
  const cell = (row: string[], index: number) => row[index] ?? "";

  const columns: PassTableColumn[] = [];
  for (const { role, label } of ROLE_COLUMNS) {
    const index = roleIndex.get(role);
    if (index == null) continue;
    const values = rows.map((row) => cell(row, index));
    if (role === "url")
      columns.push({ id: "", label, type: "link", data: values.map(toLink) });
    else if (role === "password")
      columns.push({
        id: "",
        label,
        type: "password",
        data: values.map((value) => ({ type: "password", value })),
      });
    else if (role === "totp")
      columns.push({
        id: "",
        label,
        type: "password",
        data: values.map((value) => {
          const { key, supported } = mfaKeyFrom(value);
          if (!supported) unsupportedMfa++;
          return { type: "mfa-key", value: key };
        }),
      });
    else columns.push({ id: "", label, type: "textarea", data: values });
  }
  for (const index of extraIndexes) {
    // e.g. a "fields" column nobody used
    if (rows.every((row) => cell(row, index).trim() === "")) continue;
    columns.push({
      id: "",
      label: header[index].trim(),
      type: "textarea",
      data: rows.map((row) => cell(row, index)),
    });
  }

  if (unsupportedMfa > 0)
    warnings.push(
      `${unsupportedMfa} MFA key${unsupportedMfa > 1 ? "s use" : " uses"} code settings this app doesn't support (only 6 digits, 30 seconds, SHA-1), so ${unsupportedMfa > 1 ? "their" : "its"} codes will be wrong.`,
    );
  return {
    tables: [
      {
        id: "",
        name: `Imported from ${fileName}`,
        rowIds: rows.map(() => ""),
        columns,
      },
    ],
    warnings,
  };
}

/** Exports usually include the scheme; "example.com" becomes https. Values
 *  that aren't allowed links are kept and shown as text. */
function toLink(value: string): LinkCellData {
  const url = value.trim();
  if (url === "" || /^[a-z][a-z0-9+.-]*:/i.test(url)) return { url };
  if (/^[^\s/]+\.[^\s]+$/.test(url)) return { url: `https://${url}` };
  return { url };
}

/** The Base32 key from a raw key or an otpauth:// URI, and whether its
 *  code settings are the ones this app generates. */
function mfaKeyFrom(value: string): { key: string; supported: boolean } {
  const trimmed = value.trim();
  if (!/^otpauth:/i.test(trimmed)) return { key: trimmed, supported: true };
  try {
    const params = new URL(trimmed).searchParams;
    const supported =
      ["", "SHA1"].includes((params.get("algorithm") ?? "").toUpperCase()) &&
      ["", "6"].includes(params.get("digits") ?? "") &&
      ["", "30"].includes(params.get("period") ?? "");
    return { key: params.get("secret") ?? "", supported };
  } catch {
    return { key: trimmed, supported: false };
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function isRecord(value: unknown): value is Record<string, unknown> {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000)
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

function fromBase64(text: string): Uint8Array {
  try {
    return Uint8Array.from(atob(text), (char) => char.charCodeAt(0));
  } catch {
    throw new ImportError("This backup is damaged.");
  }
}

/** Number of entries (rows) across the tables. */
export function countEntries(tables: PassTableData[]): number {
  return tables.reduce((sum, table) => sum + table.rowIds.length, 0);
}
