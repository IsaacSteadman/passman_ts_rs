// Shared vault cryptography for the browser: typed wrappers around the
// checks and signatures in passman_crypto/src/sharing.rs (which the server
// runs too), and the encryption of a vault's contents. See that file for the
// design: identities, signed member list records starting epochs, and signed
// versions.

import {
  content_hash,
  epoch_key_context,
  epoch_secret_generate,
  epoch_subkey,
  identity_bundle,
  identity_fingerprint,
  identity_generate,
  record_body,
  record_hash,
  record_sign,
  record_verify,
  safety_number,
  unwrap_key,
  version_sign,
  version_verify,
  wrap_key,
} from "passman_crypto";
import type { HistoryEntry, PassTableData } from "./PassTable";
import {
  decryptBlob,
  encryptBlob,
  fromBase64Url,
  toBase64Url,
} from "./passman_crypto_glue";

export interface Member {
  username: string;
  /** Fingerprint (base64) of the identity this member was verified with. */
  fingerprint: string;
  /** May change the vault's contents. */
  write: boolean;
  /** May change the member list. */
  manage: boolean;
}

export interface RecordBody {
  v: 1;
  vaultId: string;
  seq: number;
  prev: string | null;
  author: string;
  time: number;
  members: Member[];
  /** The epoch secret wrapped for each member (base64). */
  keys: Record<string, string>;
}

export interface VersionBody {
  v: 1;
  vaultId: string;
  epoch: number;
  version: number;
  author: string;
  time: number;
  tablesHash: string;
  historyHash: string;
  rekey: boolean;
}

/** A record whose signature and place in the chain have been checked. */
export interface VerifiedRecord {
  body: RecordBody;
  wire: Uint8Array;
}

/** What a shared vault holds: its tables and name (encrypted together) and
 *  the current epoch's history (encrypted separately, so past epochs'
 *  history can be kept without their tables). */
export interface SharedContent {
  name: string;
  tables: PassTableData[];
  history: HistoryEntry[];
}

export interface EpochKeys {
  tables: Uint8Array;
  history: Uint8Array;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// ── Frames (as `sharing::encode_frames`) ────────────────────────────────────

export function encodeFrames(parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + 4 + p.byteLength, 0));
  const view = new DataView(out.buffer);
  let at = 0;
  for (const part of parts) {
    view.setUint32(at, part.byteLength, true);
    out.set(part, at + 4);
    at += 4 + part.byteLength;
  }
  return out;
}

export function decodeFrames(data: Uint8Array, count: number): Uint8Array[] {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const frames: Uint8Array[] = [];
  let at = 0;
  while (at < data.byteLength) {
    if (at + 4 > data.byteLength) throw new Error("truncated frame");
    const len = view.getUint32(at, true);
    if (at + 4 + len > data.byteLength) throw new Error("truncated frame");
    frames.push(data.subarray(at + 4, at + 4 + len));
    at += 4 + len;
  }
  if (frames.length !== count) throw new Error(`expected ${count} frames`);
  return frames;
}

// ── Identities ──────────────────────────────────────────────────────────────

export function newIdentitySecret(): string {
  return toBase64Url(identity_generate());
}

export function identityBundle(secret: string): Uint8Array {
  return identity_bundle(fromBase64Url(secret));
}

export function fingerprintOf(bundle: Uint8Array): string {
  return toBase64Url(identity_fingerprint(bundle));
}

/** A fingerprint as 64 hex digits (how the server looks bundles up). */
export function fingerprintHex(fingerprint: string): string {
  return Array.from(fromBase64Url(fingerprint), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}

/** A fingerprint for people to read: hex digits in groups of four. */
export function formatFingerprint(fingerprint: string): string {
  return fingerprintHex(fingerprint).match(/.{4}/g)!.join(" ");
}

/** 60 digits two users read to each other to verify both identities. */
export function safetyNumber(
  userA: string,
  fingerprintA: string,
  userB: string,
  fingerprintB: string,
): string {
  return safety_number(
    userA,
    fromBase64Url(fingerprintA),
    userB,
    fromBase64Url(fingerprintB),
  );
}

// ── Records ─────────────────────────────────────────────────────────────────

/** A record's body, before it has been checked (to see who signed it). */
export function unverifiedRecordBody(wire: Uint8Array): RecordBody {
  return JSON.parse(record_body(wire)) as RecordBody;
}

/** The fingerprint the author of `wire` must have: as a manager in `prev`,
 *  or (for the first record) in the record itself. */
export function recordSignerFingerprint(
  prev: VerifiedRecord | null,
  wire: Uint8Array,
): string | null {
  const body = unverifiedRecordBody(wire);
  const members = (prev?.body ?? body).members;
  return members.find((m) => m.username === body.author)?.fingerprint ?? null;
}

/** Checks `wire` follows `prev` (throws if not). */
export function verifyRecord(
  prev: VerifiedRecord | null,
  wire: Uint8Array,
  authorBundle: Uint8Array,
): VerifiedRecord {
  const body = JSON.parse(
    record_verify(prev?.wire ?? new Uint8Array(), wire, authorBundle),
  ) as RecordBody;
  return { body, wire };
}

export function epochKeysFor(
  identitySecret: string,
  record: RecordBody,
  username: string,
): EpochKeys {
  const wrapped = record.keys[username];
  if (wrapped == null) throw new Error("not a member of this epoch");
  const secret = unwrap_key(
    fromBase64Url(identitySecret),
    fromBase64Url(wrapped),
    epoch_key_context(record.vaultId, record.seq, username),
  );
  return {
    tables: epoch_subkey(secret, "tables"),
    history: epoch_subkey(secret, "history"),
  };
}

/** Makes and signs the record after `prev` (null for a new vault) with a new
 *  epoch secret wrapped for each member, whose bundles are in `bundles`. */
export function newRecord(
  identitySecret: string,
  prev: VerifiedRecord | null,
  vaultId: string,
  author: string,
  members: Member[],
  bundles: Map<string, Uint8Array>,
): { wire: Uint8Array; keys: EpochKeys } {
  const seq = prev ? prev.body.seq + 1 : 0;
  const secret = epoch_secret_generate();
  const keys: Record<string, string> = {};
  for (const member of members) {
    const bundle = bundles.get(member.username);
    if (bundle == null || fingerprintOf(bundle) !== member.fingerprint)
      throw new Error(`no verified identity for ${member.username}`);
    keys[member.username] = toBase64Url(
      wrap_key(
        bundle,
        secret,
        epoch_key_context(vaultId, seq, member.username),
      ),
    );
  }
  const body: RecordBody = {
    v: 1,
    vaultId,
    seq,
    prev: prev ? record_hash(prev.wire) : null,
    author,
    time: Date.now(),
    members,
    keys,
  };
  return {
    wire: record_sign(fromBase64Url(identitySecret), JSON.stringify(body)),
    keys: {
      tables: epoch_subkey(secret, "tables"),
      history: epoch_subkey(secret, "history"),
    },
  };
}

// ── Versions ────────────────────────────────────────────────────────────────

/** The JSON of a vault's tables and name, as encrypted. */
export function tablesPlaintext(content: SharedContent): string {
  return JSON.stringify({ name: content.name, tables: content.tables });
}

export function sealVersion(
  identitySecret: string,
  head: Pick<VersionBody, "vaultId" | "epoch" | "version" | "author" | "rekey">,
  keys: EpochKeys,
  content: SharedContent,
): Uint8Array {
  const tables = encryptBlob(
    keys.tables,
    encoder.encode(tablesPlaintext(content)),
  );
  const history = encryptBlob(
    keys.history,
    encoder.encode(JSON.stringify(content.history)),
  );
  const body: VersionBody = {
    v: 1,
    ...head,
    time: Date.now(),
    tablesHash: content_hash(tables),
    historyHash: content_hash(history),
  };
  return version_sign(
    fromBase64Url(identitySecret),
    JSON.stringify(body),
    tables,
    history,
  );
}

/** A version's body, before it has been checked (to see who signed it). */
export function unverifiedVersionBody(wire: Uint8Array): VersionBody {
  return JSON.parse(decoder.decode(decodeFrames(wire, 4)[0])) as VersionBody;
}

/** Checks a version of `record`'s epoch (throws if invalid). */
export function verifyVersion(
  record: VerifiedRecord,
  wire: Uint8Array,
  authorBundle: Uint8Array,
): VersionBody {
  return JSON.parse(
    version_verify(record.wire, wire, authorBundle, false),
  ) as VersionBody;
}

/** Decrypts a version (checked when it was downloaded). */
export function decryptVersion(
  wire: Uint8Array,
  keys: EpochKeys,
): { body: VersionBody; content: SharedContent; tablesJson: string } {
  const [body, , tables, history] = decodeFrames(wire, 4);
  const tablesJson = decoder.decode(decryptBlob(keys.tables, tables));
  const parsed = JSON.parse(tablesJson) as {
    name: string;
    tables: PassTableData[];
  };
  return {
    body: JSON.parse(decoder.decode(body)) as VersionBody,
    tablesJson,
    content: {
      name: parsed.name,
      tables: parsed.tables,
      history: JSON.parse(
        decoder.decode(decryptBlob(keys.history, history)),
      ) as HistoryEntry[],
    },
  };
}

/** Encrypts unsaved changes for keeping on the device. */
export function encryptPending(
  keys: EpochKeys,
  content: SharedContent,
): Uint8Array<ArrayBuffer> {
  return encryptBlob(keys.tables, encoder.encode(JSON.stringify(content)));
}

export function decryptPending(
  keys: EpochKeys,
  blob: Uint8Array,
): SharedContent {
  return JSON.parse(
    decoder.decode(decryptBlob(keys.tables, blob)),
  ) as SharedContent;
}

/** Checks and decrypts an archived version's history. */
export function openArchive(
  record: VerifiedRecord,
  wire: Uint8Array,
  authorBundle: Uint8Array,
  keys: EpochKeys,
): HistoryEntry[] {
  version_verify(record.wire, wire, authorBundle, true);
  const [, , history] = decodeFrames(wire, 3);
  return JSON.parse(
    decoder.decode(decryptBlob(keys.history, history)),
  ) as HistoryEntry[];
}

/** An archived version's body, before it has been checked. */
export function unverifiedArchiveBody(wire: Uint8Array): VersionBody {
  return JSON.parse(decoder.decode(decodeFrames(wire, 3)[0])) as VersionBody;
}

export function versionEtag(body: VersionBody): string {
  return `"${body.epoch}-${body.version}"`;
}

/** A random id for a new vault: 32 hex digits. */
export function newVaultId(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}
