// Shared vaults without the UI: downloading and checking member list records
// and versions, saving with conflict checks, starting a new epoch (with a new
// key) when a manager changes the member list, and keeping vaults on the
// device so they work offline. See sharingCrypto.ts for the cryptography.

import type { Session } from "./contentArea";
import {
  type CachedSharedVault,
  deleteSharedVault,
  putSharedVault,
  sharedVaultCacheId,
} from "./deviceStore";
import { credentialHeaders } from "./loginArea";
import { mergeVaults, valuesEqual, withoutEntries } from "./merge";
import type { HistoryEntry, SharingContact, SharingData } from "./PassTable";
import { fromBase64Url, toBase64Url } from "./passman_crypto_glue";
import * as sc from "./sharingCrypto";
import { serverFetch, serverUrl } from "./serverOrigin";

export interface SharingEnv {
  session(): Session | null;
  sharing(): SharingData | null;
  /** The account's id on this device when it's remembered (its shared
   *  vaults are then kept here too), else null. */
  cacheAccount(): string | null;
}

/** The server couldn't be reached. */
export class OfflineError extends Error {
  constructor() {
    super("can't reach the server");
  }
}

/** The server refused a request. */
export class ServerError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly type: string | null,
  ) {
    super(message);
  }
}

/** Something downloaded failed its checks, so it isn't used: the server (or
 *  whoever controls it) changed or forged it. */
export class TamperError extends Error {}

/** A shared vault as listed by the server. */
export interface ServerVaultInfo {
  id: string;
  /** The latest record's seq, and the oldest one the server keeps. */
  seq: number;
  firstSeq: number;
  etag: string;
  /** Past epochs' history, with the size of its ciphertext. */
  archives: { epoch: number; size: number }[];
  /** Members leaving, with their (or a manager's) signed statement. */
  leaving: { username: string; statement: string }[];
  /** What counts toward `maxDataSize`: the current version's encrypted
   *  tables and history, and the archives'. */
  usage: number;
  maxDataSize: number;
  maxMembers: number;
  /** How many member list records the server keeps; older ones go, with
   *  their epochs' history. */
  maxRecords: number;
  writable: boolean;
}

/** What saving some contents does to fit the vault's size limit. */
export interface StoragePlan {
  /** The size it would use, and the limit. */
  usage: number;
  max: number | null;
  /** Past epochs whose history the server drops to make room (oldest
   *  first). */
  droppedArchives: number[];
  /** How many of the oldest history entries are removed. */
  trimmedEntries: number;
  /** By how much it's too large even so (0 if it fits). */
  over: number;
}

/** "N KB" for people to read. */
export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

async function serverError(response: Response): Promise<ServerError> {
  const text = await response.text();
  try {
    const body = JSON.parse(text) as {
      type?: string;
      message?: string;
      policy_message?: string;
    };
    return new ServerError(
      body.policy_message ?? body.message ?? text,
      response.status,
      body.type ?? null,
    );
  } catch {
    return new ServerError(text, response.status, null);
  }
}

/** Requests to the sharing routes as the unlocked user, and the identity
 *  bundles they need, checked against their fingerprints. */
export class SharingClient {
  private generation = 0;
  private bundles = new Map<string, Uint8Array>();

  constructor(readonly env: SharingEnv) {}

  /** Forgets everything when the session ends; requests still in flight
   *  then fail. */
  reset(): void {
    this.generation++;
    this.bundles.clear();
  }

  username(): string {
    const session = this.env.session();
    if (session == null) throw new OfflineError();
    return session.username;
  }

  identitySecret(): string {
    const sharing = this.env.sharing();
    if (sharing == null) throw new Error("sharing isn't set up");
    return sharing.identitySecret;
  }

  async request(
    method: string,
    path: string,
    init: {
      query?: Record<string, string>;
      json?: unknown;
      body?: Uint8Array<ArrayBuffer>;
      headers?: Record<string, string>;
    } = {},
  ): Promise<Response> {
    const session = this.env.session();
    if (session == null) throw new OfflineError();
    const started = this.generation;
    const url = serverUrl(path);
    url.searchParams.set("username", session.username);
    if (session.serverNs != null)
      url.searchParams.set("server_ns", session.serverNs);
    for (const [k, v] of Object.entries(init.query ?? {}))
      url.searchParams.set(k, v);
    const headers: Record<string, string> = {
      ...credentialHeaders(session.authKeyB64, session.serverPass),
      ...init.headers,
    };
    let body: BodyInit | undefined;
    if (init.json !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(init.json);
    } else if (init.body !== undefined) {
      headers["Content-Type"] = "application/octet-stream";
      body = init.body;
    }
    let response: Response;
    try {
      response = await serverFetch(url, {
        method,
        headers,
        body,
        cache: "no-store",
      });
    } catch {
      throw new OfflineError();
    }
    if (started !== this.generation) throw new OfflineError();
    return response;
  }

  /** Like `request`, but throws a `ServerError` unless it succeeded. */
  async ok(...args: Parameters<SharingClient["request"]>): Promise<Response> {
    const response = await this.request(...args);
    if (!response.ok) throw await serverError(response);
    return response;
  }

  /** The identity with this fingerprint (any ever published). */
  async bundleByFingerprint(fingerprint: string): Promise<Uint8Array> {
    const cached = this.bundles.get(fingerprint);
    if (cached) return cached;
    const response = await this.ok("GET", "/identity", {
      query: { fingerprint: sc.fingerprintHex(fingerprint) },
    });
    const { bundle } = (await response.json()) as { bundle: string };
    const bytes = fromBase64Url(bundle);
    if (sc.fingerprintOf(bytes) !== fingerprint)
      throw new TamperError("the server sent the wrong identity");
    this.bundles.set(fingerprint, bytes);
    return bytes;
  }

  /** A user's current identity, or null if they haven't set up sharing. */
  async identityOf(
    username: string,
  ): Promise<{ bundle: Uint8Array; fingerprint: string } | null> {
    const response = await this.request("GET", "/identity", {
      query: { user: username },
    });
    if (response.status === 404) return null;
    if (!response.ok) throw await serverError(response);
    const { bundle } = (await response.json()) as { bundle: string };
    const bytes = fromBase64Url(bundle);
    const fingerprint = sc.fingerprintOf(bytes);
    this.bundles.set(fingerprint, bytes);
    return { bundle: bytes, fingerprint };
  }

  async publishIdentity(identitySecret: string): Promise<void> {
    await this.ok("PUT", "/identity", {
      json: { bundle: toBase64Url(sc.identityBundle(identitySecret)) },
    });
  }

  async listVaults(): Promise<ServerVaultInfo[]> {
    const response = await this.ok("GET", "/shared-vaults");
    return ((await response.json()) as { vaults: ServerVaultInfo[] }).vaults;
  }
}

interface Synced {
  wire: Uint8Array;
  body: sc.VersionBody;
  content: sc.SharedContent;
  tablesJson: string;
}

/** Merges a vault's contents: tables and history as for the user's own vault,
 *  the name as one value. Conflicts resolve to `remote`. */
function mergeContent(
  base: sc.SharedContent,
  local: sc.SharedContent,
  remote: sc.SharedContent,
): { merged: sc.SharedContent; conflicts: string[] } {
  const { merged, conflicts } = mergeVaults(base, local, remote);
  let name = remote.name;
  if (remote.name === base.name) name = local.name;
  else if (local.name !== base.name && local.name !== remote.name)
    conflicts.push("The vault's name");
  const minHistory =
    remote.minHistory === base.minHistory
      ? local.minHistory
      : remote.minHistory;
  const content: sc.SharedContent = {
    name,
    tables: merged.tables,
    history: merged.history,
  };
  if (minHistory != null) content.minHistory = minHistory;
  return { merged: content, conflicts };
}

const HISTORY_LIMIT = 100;

export class SharedVault {
  /** The member list records, from the first, all checked. */
  records: sc.VerifiedRecord[];
  /** The version last downloaded or saved, and this session's contents. */
  synced: Synced;
  data: sc.SharedContent;
  info: ServerVaultInfo | null = null;
  /** For the UI: what's happening, and conflicts resolved in favour of
   *  someone else's changes since it was last shown. */
  status = "";
  conflicts: string[] = [];
  /** Unsaved changes that can no longer be saved, since this user can't
   *  change the vault anymore (or was removed from it). */
  stranded: sc.SharedContent | null = null;
  /** No longer a member (removed, left, or the vault was deleted). */
  removed = false;
  /** An invitation the user hasn't accepted: the vault is shown as one, and
   *  isn't saved to, changed or kept on the device. */
  pending = false;
  /** Members leaving whose signed statement checked out. */
  leaving: string[] = [];
  onChange: () => void = () => {};
  private queue: Promise<void> = Promise.resolve();

  private constructor(
    readonly client: SharingClient,
    readonly id: string,
    records: sc.VerifiedRecord[],
    synced: Synced,
    data: sc.SharedContent,
  ) {
    this.records = records;
    this.synced = synced;
    this.data = data;
  }

  get latest(): sc.VerifiedRecord {
    return this.records[this.records.length - 1];
  }

  get me(): sc.Member | undefined {
    const username = this.client.username();
    return this.latest.body.members.find((m) => m.username === username);
  }

  canWrite(): boolean {
    return (this.me?.write ?? false) && this.info?.writable !== false;
  }

  canManage(): boolean {
    return (this.me?.manage ?? false) && this.info?.writable !== false;
  }

  /** The managers other than this user whose identity isn't the one the
   *  user verified: anyone with a user's public identity can add them to a
   *  vault, so the UI says when it's run by someone unverified. */
  unverifiedManagers(contacts: Record<string, SharingContact>): string[] {
    const username = this.client.username();
    return this.latest.body.members
      .filter(
        (m) =>
          m.manage &&
          m.username !== username &&
          contacts[m.username]?.fingerprint !== m.fingerprint,
      )
      .map((m) => m.username);
  }

  hasUnsavedChanges(): boolean {
    return !valuesEqual(this.data, this.synced.content);
  }

  /** The keys of an epoch this user was a member in. */
  private keysFor(epoch: number): sc.EpochKeys {
    const record = this.records.find((r) => r.body.seq === epoch);
    if (record == null) throw new Error(`no record of epoch ${epoch}`);
    return sc.epochKeysFor(
      this.client.identitySecret(),
      record.body,
      this.client.username(),
    );
  }

  // ── Creating and loading ──────────────────────────────────────────────────

  /** Creates a vault with this user as its only member. */
  static async create(
    client: SharingClient,
    name: string,
  ): Promise<SharedVault> {
    const secret = client.identitySecret();
    const username = client.username();
    const own = sc.identityBundle(secret);
    const me: sc.Member = {
      username,
      fingerprint: sc.fingerprintOf(own),
      write: true,
      manage: true,
    };
    const id = sc.newVaultId();
    const { wire: recordWire, keys } = sc.newRecord(
      secret,
      null,
      id,
      username,
      [me],
      new Map([[username, own]]),
    );
    const content: sc.SharedContent = { name, tables: [], history: [] };
    const versionWire = sc.sealVersion(
      secret,
      { vaultId: id, epoch: 0, version: 1, author: username, rekey: false },
      keys,
      content,
    );
    await client.ok("POST", "/shared-vaults", {
      body: sc.encodeFrames([recordWire, versionWire]),
    });
    const vault = new SharedVault(
      client,
      id,
      [sc.verifyRecord(null, recordWire, own)],
      {
        wire: versionWire,
        body: sc.unverifiedVersionBody(versionWire),
        content,
        tablesJson: sc.tablesPlaintext(content),
      },
      structuredClone(content),
    );
    vault.persist();
    return vault;
  }

  /** Downloads a vault and checks its whole member list from the start. */
  static async download(
    client: SharingClient,
    info: ServerVaultInfo,
  ): Promise<SharedVault> {
    const records = await SharedVault.fetchRecords(client, info.id, []);
    const keys = sc.epochKeysFor(
      client.identitySecret(),
      records[records.length - 1].body,
      client.username(),
    );
    const synced = await SharedVault.fetchVersion(
      client,
      info.id,
      records,
      keys,
      null,
    );
    const vault = new SharedVault(
      client,
      info.id,
      records,
      synced,
      structuredClone(synced.content),
    );
    vault.info = info;
    vault.refreshPending();
    vault.persist();
    return vault;
  }

  /** A vault kept on this device (checked when it was stored). */
  static fromCache(
    client: SharingClient,
    cached: CachedSharedVault,
  ): SharedVault {
    const records = cached.records.map((wire) => ({
      wire,
      body: sc.unverifiedRecordBody(wire),
    }));
    const keysFor = (epoch: number) => {
      const record = records.find((r) => r.body.seq === epoch);
      if (record == null) throw new Error(`no record of epoch ${epoch}`);
      return sc.epochKeysFor(
        client.identitySecret(),
        record.body,
        client.username(),
      );
    };
    const syncedEpoch = sc.unverifiedVersionBody(cached.synced).epoch;
    const synced = {
      wire: cached.synced,
      ...sc.decryptVersion(cached.synced, keysFor(syncedEpoch)),
    };
    const data = cached.pending
      ? sc.decryptPending(keysFor(cached.pending.epoch), cached.pending.blob)
      : structuredClone(synced.content);
    const vault = new SharedVault(
      client,
      cached.vaultId,
      records,
      synced,
      data,
    );
    vault.refreshPending();
    return vault;
  }

  // ── Downloading ───────────────────────────────────────────────────────────

  /** Downloads the records after `known` and checks each follows the one
   *  before, signed by a manager of it. The server keeps only a vault's
   *  latest records: without `known` (or if it dropped some this device
   *  hasn't seen), the oldest it has is checked as the start of the chain,
   *  like a first record. */
  private static async fetchRecords(
    client: SharingClient,
    id: string,
    known: sc.VerifiedRecord[],
  ): Promise<sc.VerifiedRecord[]> {
    const last = known[known.length - 1];
    const wanted = last ? last.body.seq + 1 : 0;
    const response = await client.ok("GET", `/shared-vaults/${id}/records`, {
      query: { from: String(wanted) },
    });
    const { from, records } = (await response.json()) as {
      from: number;
      records: string[];
    };
    if (from < wanted)
      throw new TamperError("the server sent member lists out of order");
    // a gap: start again from what the server keeps (still newer than
    // what this device had)
    const all = from === wanted ? [...known] : [];
    for (const encoded of records) {
      const wire = fromBase64Url(encoded);
      const prev = all[all.length - 1] ?? null;
      const fingerprint = sc.recordSignerFingerprint(prev, wire);
      if (fingerprint == null)
        throw new TamperError(
          "a change to the member list wasn't made by a member",
        );
      const bundle = await client.bundleByFingerprint(fingerprint);
      try {
        all.push(
          prev == null && sc.unverifiedRecordBody(wire).seq > 0
            ? sc.verifyAnchorRecord(wire, bundle)
            : sc.verifyRecord(prev, wire, bundle),
        );
      } catch (e) {
        throw new TamperError(`a change to the member list is invalid: ${e}`);
      }
    }
    if (all.length === 0 || all[0].body.vaultId !== id)
      throw new TamperError("the member list belongs to another vault");
    if (last && all[all.length - 1].body.seq < last.body.seq)
      throw new TamperError("the server sent an older member list");
    return all;
  }

  /** Downloads the current version and checks it was saved by someone
   *  allowed to. `previous` is the version this device has, if any. */
  private static async fetchVersion(
    client: SharingClient,
    id: string,
    records: sc.VerifiedRecord[],
    keys: sc.EpochKeys,
    previous: Synced | null,
  ): Promise<Synced> {
    const response = await client.ok("GET", `/shared-vaults/${id}/version`);
    const wire = new Uint8Array(await response.arrayBuffer());
    const claimed = sc.unverifiedVersionBody(wire);
    const record = records[records.length - 1];
    if (claimed.epoch !== record.body.seq)
      throw new TamperError("the vault doesn't match its member list");
    const author = record.body.members.find(
      (m) => m.username === claimed.author,
    );
    if (author == null)
      throw new TamperError(
        "the vault was saved by someone who isn't a member",
      );
    const bundle = await client.bundleByFingerprint(author.fingerprint);
    let body: sc.VersionBody;
    try {
      body = sc.verifyVersion(record, wire, bundle);
    } catch (e) {
      throw new TamperError(`the vault is invalid: ${e}`);
    }
    if (previous && body.version < previous.body.version)
      throw new TamperError("the server sent an older version of the vault");
    const opened = { wire, ...sc.decryptVersion(wire, keys) };
    // a manager who can't write may only re-encrypt the tables when changing
    // the member list; this device can check that if it has the version before
    if (
      body.rekey &&
      !author.write &&
      previous?.body.version === body.version - 1 &&
      !valuesEqual(
        JSON.parse(opened.tablesJson),
        JSON.parse(previous.tablesJson),
      )
    )
      throw new TamperError(
        `${author.username} changed the tables while only allowed to re-encrypt them`,
      );
    return opened;
  }

  /** Merges `latest` (the server's version) into this session's changes. */
  private adopt(latest: Synced): void {
    const { merged, conflicts } = mergeContent(
      this.synced.content,
      this.data,
      latest.content,
    );
    this.synced = latest;
    this.data = merged;
    this.conflicts.push(...conflicts);
  }

  private async pullRecords(): Promise<void> {
    const before = this.latest.body.seq;
    this.records = await SharedVault.fetchRecords(
      this.client,
      this.id,
      this.records,
    );
    if (this.latest.body.seq !== before && this.me == null) this.removed = true;
  }

  private async pullVersion(): Promise<void> {
    this.adopt(
      await SharedVault.fetchVersion(
        this.client,
        this.id,
        this.records,
        this.keysFor(this.latest.body.seq),
        this.synced,
      ),
    );
  }

  private enqueue(task: () => Promise<void>): Promise<void> {
    this.queue = this.queue.then(task).catch((e) => this.fail(e));
    return this.queue;
  }

  private fail(e: unknown): void {
    if (e instanceof OfflineError)
      this.status = this.hasUnsavedChanges()
        ? this.client.env.cacheAccount()
          ? "Offline — changes are kept on this device and saved when you're back online"
          : "Offline — changes aren't saved yet; keep this page open until you're back online"
        : "Offline";
    else if (e instanceof ServerError && e.status === 404) this.lose();
    else if (e instanceof TamperError)
      this.status = `⚠ Not updated: ${e.message}. This could mean the server was tampered with.`;
    else this.status = `⚠ ${e instanceof Error ? e.message : String(e)}`;
    this.onChange();
  }

  /** The server no longer lists the vault for this user. */
  markRemoved(): void {
    if (this.removed) return;
    this.lose();
    this.onChange();
  }

  /** No longer a member: keeps unsaved changes so they can be copied. */
  private lose(): void {
    this.removed = true;
    if (this.hasUnsavedChanges()) this.stranded = this.data;
    else void this.forget();
  }

  /** Brings this device's copy up to date with the server (whose list entry
   *  is `info`), then saves this session's changes, and removes members who
   *  left if this user manages the vault. */
  sync(info: ServerVaultInfo): Promise<void> {
    return this.enqueue(async () => {
      this.info = info;
      if (info.seq < this.latest.body.seq)
        throw new TamperError("the server sent an older member list");
      if (info.seq > this.latest.body.seq) await this.pullRecords();
      if (this.removed) return this.lose();
      this.refreshPending();
      if (info.etag !== sc.versionEtag(this.synced.body))
        await this.pullVersion();
      this.status = "";
      this.leaving = await this.checkLeaving(info);
      this.persist();
      if (this.pending) return this.onChange();
      if (this.hasUnsavedChanges()) await this.saveNow();
      if (this.canManage() && this.leaving.length > 0)
        await this.rotateNow(
          this.latest.body.members.filter(
            (m) => !this.leaving.includes(m.username),
          ),
        );
      this.onChange();
    });
  }

  /** The members the server says are leaving whose statement (by them or a
   *  manager, in the current epoch) checks out. The server alone can't make
   *  managers' browsers remove anyone. */
  private async checkLeaving(info: ServerVaultInfo): Promise<string[]> {
    const valid: string[] = [];
    for (const { username, statement } of info.leaving) {
      try {
        const wire = fromBase64Url(statement);
        const claimed = sc.unverifiedLeaveBody(wire);
        const author = this.latest.body.members.find(
          (m) => m.username === claimed.author,
        );
        if (author == null) throw new Error("not by a member");
        const body = sc.verifyLeave(
          this.latest,
          wire,
          await this.client.bundleByFingerprint(author.fingerprint),
        );
        if (body.member !== username) throw new Error("about someone else");
        valid.push(username);
      } catch (e) {
        if (e instanceof OfflineError) throw e;
        this.status = `⚠ Ignored the server's word that ${username} is leaving: ${e instanceof Error ? e.message : e}`;
      }
    }
    return valid;
  }

  // ── Saving ────────────────────────────────────────────────────────────────

  /** Records a change made in the tables and saves it. */
  record(entry: HistoryEntry): Promise<void> {
    this.data.history.push(entry);
    if (this.data.history.length > HISTORY_LIMIT)
      this.data.history.splice(0, this.data.history.length - HISTORY_LIMIT);
    return this.save();
  }

  /** Removes entries from the current epoch's history and saves (past
   *  epochs' archived history can't be changed). */
  deleteHistory(entries: HistoryEntry[]): Promise<void> {
    this.data.history = withoutEntries(this.data.history, entries);
    return this.save();
  }

  save(): Promise<void> {
    this.persist();
    return this.enqueue(async () => {
      await this.saveNow();
      this.onChange();
    });
  }

  /** What saving `content` does to fit the vault's size limit: the server
   *  drops the oldest archived history first, then the oldest entries of the
   *  current history go, down to the vault's minimum. */
  planStorage(content: sc.SharedContent = this.data): StoragePlan {
    const max = this.info?.maxDataSize ?? null;
    const archives = [...(this.info?.archives ?? [])].sort(
      (a, b) => a.epoch - b.epoch,
    );
    let archived = archives.reduce((n, a) => n + a.size, 0);
    let usage = sc.contentLen(content) + archived;
    const plan: StoragePlan = {
      usage,
      max,
      droppedArchives: [],
      trimmedEntries: 0,
      over: 0,
    };
    if (max == null) return plan;
    for (const archive of archives) {
      if (usage <= max) break;
      plan.droppedArchives.push(archive.epoch);
      archived -= archive.size;
      usage -= archive.size;
    }
    const keep = Math.max(0, content.minHistory ?? sc.DEFAULT_MIN_HISTORY);
    let history = content.history;
    while (usage > max && history.length > keep) {
      history = history.slice(1);
      plan.trimmedEntries++;
      usage = sc.contentLen({ ...content, history }) + archived;
    }
    plan.usage = usage;
    plan.over = Math.max(0, usage - max);
    return plan;
  }

  /** When the epoch `epoch` started, for people to read ("now" for the one
   *  a member change is about to start). */
  epochDate(epoch: number): string {
    if (epoch > this.latest.body.seq) return "now";
    const record = this.records.find((r) => r.body.seq === epoch);
    return record
      ? new Date(record.body.time).toLocaleString()
      : "the oldest member list kept";
  }

  private async saveNow(): Promise<void> {
    // a save refused because someone else saved first (or the member list
    // changed) is retried after merging their changes
    for (let attempt = 0; attempt < 4; attempt++) {
      if (!this.hasUnsavedChanges()) return;
      if (!this.canWrite()) {
        this.stranded = this.data;
        return;
      }
      const plan = this.planStorage();
      if (plan.over > 0) {
        this.status = `⚠ Not saved: the vault would be ${formatSize(plan.over)} over its ${formatSize(plan.max ?? 0)} limit, even keeping only the newest ${this.data.minHistory ?? sc.DEFAULT_MIN_HISTORY} history entries. Remove something (or keep less history) to save`;
        return;
      }
      if (plan.trimmedEntries > 0)
        this.data.history.splice(0, plan.trimmedEntries);
      const username = this.client.username();
      const content = structuredClone(this.data);
      const wire = sc.sealVersion(
        this.client.identitySecret(),
        {
          vaultId: this.id,
          epoch: this.latest.body.seq,
          version: this.synced.body.version + 1,
          author: username,
          rekey: false,
        },
        this.keysFor(this.latest.body.seq),
        content,
      );
      this.status = "Saving…";
      this.onChange();
      const response = await this.client.request(
        "PUT",
        `/shared-vaults/${this.id}/version`,
        {
          body: wire as Uint8Array<ArrayBuffer>,
          headers: { "If-Match": sc.versionEtag(this.synced.body) },
        },
      );
      if (response.ok) {
        this.synced = {
          wire,
          body: sc.unverifiedVersionBody(wire),
          content,
          tablesJson: sc.tablesPlaintext(content),
        };
        if (this.info)
          this.info = {
            ...this.info,
            etag: sc.versionEtag(this.synced.body),
            archives: this.info.archives.filter(
              (a) => !plan.droppedArchives.includes(a.epoch),
            ),
            usage: plan.usage,
          };
        const notes = [];
        if (plan.droppedArchives.length > 0)
          notes.push(
            `deleted the history from before ${this.epochDate(plan.droppedArchives[plan.droppedArchives.length - 1] + 1)}`,
          );
        if (plan.trimmedEntries > 0)
          notes.push(
            `removed the ${plan.trimmedEntries} oldest history ${plan.trimmedEntries === 1 ? "entry" : "entries"}`,
          );
        this.status =
          notes.length > 0
            ? `Saved — ${notes.join(" and ")} to stay within the vault's size limit`
            : "Saved";
        this.persist();
        return;
      }
      const error = await serverError(response);
      if (error.status === 412) {
        await this.pullVersion();
        continue;
      }
      if (error.type === "E_EPOCH_CHANGED") {
        await this.pullRecords();
        if (this.removed) return this.lose();
        await this.pullVersion();
        continue;
      }
      throw error;
    }
    throw new Error("the vault keeps changing; try again");
  }

  /** Gives up unsaved changes that can't be saved (see `stranded`). */
  discardStranded(): void {
    this.stranded = null;
    this.data = structuredClone(this.synced.content);
    if (this.removed) void this.forget();
    else this.persist();
    this.onChange();
  }

  // ── Member list ───────────────────────────────────────────────────────────

  /** Replaces the member list (managers only), starting a new epoch: the
   *  vault is re-encrypted with a new key that only `members` get. */
  changeMembers(members: sc.Member[]): Promise<void> {
    return this.enqueue(async () => {
      await this.rotateNow(members);
      if (this.hasUnsavedChanges()) await this.saveNow();
      this.onChange();
    });
  }

  private async rotateNow(members: sc.Member[]): Promise<void> {
    for (let attempt = 0; attempt < 3; attempt++) {
      const secret = this.client.identitySecret();
      const username = this.client.username();
      const bundles = new Map<string, Uint8Array>();
      for (const member of members)
        bundles.set(
          member.username,
          await this.client.bundleByFingerprint(member.fingerprint),
        );
      const { wire: recordWire, keys } = sc.newRecord(
        secret,
        this.latest,
        this.id,
        username,
        members,
        bundles,
      );
      // the tables exactly as they are, re-encrypted; the new epoch starts
      // its own history
      const content: sc.SharedContent = {
        name: this.synced.content.name,
        tables: this.synced.content.tables,
        minHistory: this.synced.content.minHistory,
        history: [],
      };
      const versionWire = sc.sealVersion(
        secret,
        {
          vaultId: this.id,
          epoch: this.latest.body.seq + 1,
          version: this.synced.body.version + 1,
          author: username,
          rekey: true,
        },
        keys,
        content,
      );
      this.status = "Updating members…";
      this.onChange();
      const response = await this.client.request(
        "POST",
        `/shared-vaults/${this.id}/records`,
        {
          body: sc.encodeFrames([recordWire, versionWire]),
          headers: { "If-Match": sc.versionEtag(this.synced.body) },
        },
      );
      if (response.status === 412) {
        // someone saved first: start from their version
        await this.pullRecords();
        await this.pullVersion();
        continue;
      }
      if (!response.ok) throw await serverError(response);
      const maxRecords = this.info?.maxRecords ?? Infinity;
      this.records = [
        ...this.records,
        sc.verifyRecord(this.latest, recordWire, sc.identityBundle(secret)),
      ].slice(-maxRecords);
      this.adopt({
        wire: versionWire,
        body: sc.unverifiedVersionBody(versionWire),
        content,
        tablesJson: sc.tablesPlaintext(content),
      });
      if (this.info)
        this.info = {
          ...this.info,
          seq: this.latest.body.seq,
          firstSeq: this.records[0].body.seq,
          etag: sc.versionEtag(this.synced.body),
          leaving: [],
        };
      this.leaving = [];
      this.status = "Members updated";
      this.persist();
      return;
    }
    throw new Error("the vault keeps changing; try again");
  }

  /** What changing the member list drops: the oldest records beyond the
   *  vault's limit (with their epochs' history), and archived history that
   *  no longer fits once this epoch's history is archived too. */
  planMemberChange(): { droppedRecords: number; droppedEpochs: number[] } {
    const info = this.info;
    if (info == null) return { droppedRecords: 0, droppedEpochs: [] };
    const seqs = this.records.map((r) => r.body.seq);
    const droppedRecords = Math.max(0, seqs.length + 1 - info.maxRecords);
    const dropped = new Set(seqs.slice(0, droppedRecords));
    const archives = [
      ...info.archives.filter((a) => !dropped.has(a.epoch)),
      {
        epoch: this.latest.body.seq,
        size: sc.ciphertextLen(JSON.stringify(this.synced.content.history)),
      },
    ].sort((a, b) => a.epoch - b.epoch);
    let usage =
      sc.contentLen({ ...this.synced.content, history: [] }) +
      archives.reduce((n, a) => n + a.size, 0);
    for (const archive of archives) {
      if (usage <= info.maxDataSize) break;
      dropped.add(archive.epoch);
      usage -= archive.size;
    }
    return {
      droppedRecords,
      // the epochs whose (archived) history is lost
      droppedEpochs: [...dropped]
        .filter(
          (e) =>
            info.archives.some((a) => a.epoch === e) ||
            e === this.latest.body.seq,
        )
        .sort((a, b) => a - b),
    };
  }

  /** The record that made this user a member this time (the first of an
   *  unbroken run of records listing them), and whether that's certain: the
   *  run may go back past the oldest record kept. */
  private joined(): {
    record: sc.VerifiedRecord;
    index: number;
    known: boolean;
  } | null {
    const username = this.client.username();
    let index = -1;
    for (let i = this.records.length - 1; i >= 0; i--) {
      if (!this.records[i].body.members.some((m) => m.username === username))
        break;
      index = i;
    }
    if (index < 0) return null;
    const record = this.records[index];
    return { record, index, known: index > 0 || record.body.seq === 0 };
  }

  /** Who added this user, with the identity they signed it with. */
  inviter(): { username: string; fingerprint: string } | null {
    const joined = this.joined();
    if (joined == null) return null;
    const prev = this.records[joined.index - 1] ?? null;
    const fingerprint = sc.recordSignerFingerprint(prev, joined.record.wire);
    return fingerprint == null
      ? null
      : { username: joined.record.body.author, fingerprint };
  }

  /** Whether the user accepted this vault since they were (last) added
   *  (as recorded in their own vault). */
  isAccepted(): boolean {
    const at = this.client.env.sharing()?.accepted?.[this.id];
    const joined = this.joined();
    if (at == null || joined == null) return false;
    return !joined.known || at >= joined.record.body.seq;
  }

  /** Updates `pending` from the user's accepted vaults. */
  refreshPending(): void {
    this.pending = !this.isAccepted();
  }

  /** Signs and sends a statement that `member` (this user, or one this
   *  manager is removing) is leaving: they can no longer open it, and a
   *  manager's browser removes them with a new key. */
  async sendLeave(member: string): Promise<void> {
    const statement = sc.signLeave(
      this.client.identitySecret(),
      this.latest,
      member,
      this.client.username(),
    );
    await this.client.ok("POST", `/shared-vaults/${this.id}/leave`, {
      body: statement,
    });
  }

  /** Leaves the vault (or declines the invitation). */
  async leave(): Promise<void> {
    await this.sendLeave(this.client.username());
    this.removed = true;
    await this.forget();
  }

  async deleteVault(): Promise<void> {
    await this.client.ok("DELETE", `/shared-vaults/${this.id}`);
    this.removed = true;
    await this.forget();
  }

  // ── History ───────────────────────────────────────────────────────────────

  /** History of the past epochs this user was a member in (oldest first),
   *  then the current one's. */
  async fullHistory(): Promise<HistoryEntry[]> {
    const username = this.client.username();
    const past: HistoryEntry[] = [];
    for (const record of this.records.slice(0, -1)) {
      const epoch = record.body.seq;
      const member = record.body.members.find((m) => m.username === username);
      if (member == null) continue;
      const response = await this.client.request(
        "GET",
        `/shared-vaults/${this.id}/archive/${epoch}`,
      );
      // dropped by the server to make room
      if (response.status === 404) continue;
      if (!response.ok) throw await serverError(response);
      const wire = new Uint8Array(await response.arrayBuffer());
      const claimed = sc.unverifiedArchiveBody(wire);
      const author = record.body.members.find(
        (m) => m.username === claimed.author,
      );
      if (author == null)
        throw new TamperError("history saved by a non-member");
      past.push(
        ...sc.openArchive(
          record,
          wire,
          await this.client.bundleByFingerprint(author.fingerprint),
          this.keysFor(epoch),
        ),
      );
    }
    return [...past, ...this.data.history];
  }

  // ── This device ───────────────────────────────────────────────────────────

  /** Keeps the vault on the device if the account is remembered. */
  persist(): void {
    const account = this.client.env.cacheAccount();
    if (account == null || this.removed || this.pending) return;
    const epoch = this.latest.body.seq;
    void putSharedVault({
      id: sharedVaultCacheId(account, this.id),
      account,
      vaultId: this.id,
      records: this.records.map((r) => r.wire),
      synced: this.synced.wire,
      pending: this.hasUnsavedChanges()
        ? { epoch, blob: sc.encryptPending(this.keysFor(epoch), this.data) }
        : null,
    }).catch((e) => {
      this.status = `⚠ Couldn't keep this vault on the device: ${e}`;
      this.onChange();
    });
  }

  async forget(): Promise<void> {
    const account = this.client.env.cacheAccount();
    if (account != null)
      await deleteSharedVault(sharedVaultCacheId(account, this.id));
  }
}
