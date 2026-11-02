//! Storage of shared vaults (see `passman_crypto::sharing` for what is in
//! them). The server can't read them, and checks every record and version it
//! stores the same way members' browsers do, so it doesn't store anything a
//! member would refuse.
//!
//! Each vault is a directory in `server_data/.shared/vaults/<id>/`:
//! - `meta.json`: its creator, limits, the policy it was created under and
//!   the members leaving it
//! - `records/<seq>`: its latest member list records (older ones are dropped
//!   beyond its limit)
//! - `current`: its current version
//! - `archive/<epoch>`: the last version of each past epoch without its
//!   tables, for reading that epoch's history
//!
//! Identity bundles are in `server_data/.shared/identities/`: each user's
//! current one in `users/<username>`, and every bundle still needed (someone's
//! current one, or one named in a record kept) in `bundles/<fingerprint>`.
//!
//! Locking: each vault has a lock, held while reading (shared) or changing
//! (exclusive) its files, and never while waiting for a client. What the
//! server needs to know about a vault without its lock (who's in it, for
//! listing and checking requests) is in the registry, a plain mutex that is
//! never held across an await; whoever changes a vault updates its summary
//! there while holding the vault's lock.

use crate::server_policy::VaultLimits;
use passman_crypto::sharing::{self, RecordBody, VersionBody};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    io::ErrorKind,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};
use tokio::{fs, io::AsyncWriteExt, sync::RwLock};

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VaultMeta {
    /// The policy the vault was created under: it gets its count back when
    /// the vault is deleted, and the vault can't be changed once it's gone.
    pub policy_ns: Option<String>,
    /// Whose count of shared vaults it uses.
    pub creator: String,
    pub limits: VaultLimits,
    /// Members leaving, with the signed statement saying so (base64): they
    /// can no longer open the vault, and the next record (made by a
    /// manager's browser) must remove them.
    pub leaving: BTreeMap<String, String>,
}

#[derive(Clone, Copy)]
pub struct ArchiveInfo {
    /// The file's size.
    pub len: u64,
    /// Its encrypted history's size, which counts toward the vault's limit.
    pub content_len: u64,
}

/// What the server keeps in memory about a vault, under its lock.
pub struct VaultState {
    pub meta: VaultMeta,
    /// The latest record.
    pub record: RecordBody,
    pub record_wire: Vec<u8>,
    /// The oldest record kept.
    pub first_seq: u64,
    /// The members' fingerprints in each record kept, by seq.
    pub record_fingerprints: BTreeMap<u64, Vec<String>>,
    /// The current version's body, size and content size.
    pub version: VersionBody,
    pub version_len: u64,
    pub version_content_len: u64,
    /// The archived versions, by epoch.
    pub archives: BTreeMap<u64, ArchiveInfo>,
    /// Set when the vault was deleted while a request waited for its lock.
    pub deleted: bool,
}

impl VaultState {
    pub fn is_member(&self, username: &str) -> bool {
        !self.deleted
            && self.record.member(username).is_some()
            && !self.meta.leaving.contains_key(username)
    }

    /// What counts toward the vault's size limit: the encrypted tables and
    /// history of the current version and the archives.
    pub fn usage(&self) -> u64 {
        self.version_content_len + self.archives.values().map(|a| a.content_len).sum::<u64>()
    }

    pub fn summary(&self) -> Summary {
        Summary {
            creator: self.meta.creator.clone(),
            policy_ns: self.meta.policy_ns.clone(),
            limits: self.meta.limits,
            members: self
                .record
                .members
                .iter()
                .map(|m| (m.username.clone(), (m.write, m.manage)))
                .collect(),
            leaving: self.meta.leaving.clone(),
            seq: self.record.seq,
            first_seq: self.first_seq,
            etag: version_etag(&self.version),
            archives: self
                .archives
                .iter()
                .map(|(epoch, a)| (*epoch, a.content_len))
                .collect(),
            usage: self.usage(),
            fingerprints: self
                .record_fingerprints
                .values()
                .flatten()
                .cloned()
                .collect(),
        }
    }
}

/// The version's ETag: its epoch and number, which only ever increase.
pub fn version_etag(version: &VersionBody) -> String {
    format!("\"{}-{}\"", version.epoch, version.version)
}

/// What the server knows about a vault without waiting for its lock (as of
/// its last change).
pub struct Summary {
    pub creator: String,
    pub policy_ns: Option<String>,
    pub limits: VaultLimits,
    /// The latest record's members: (may write, may manage).
    pub members: BTreeMap<String, (bool, bool)>,
    pub leaving: BTreeMap<String, String>,
    pub seq: u64,
    pub first_seq: u64,
    pub etag: String,
    /// (epoch, content size) of each archive.
    pub archives: Vec<(u64, u64)>,
    pub usage: u64,
    /// Fingerprints named in the records kept (their bundles are kept).
    pub fingerprints: BTreeSet<String>,
}

impl Summary {
    /// A member who hasn't left: (may write, may manage).
    pub fn member(&self, username: &str) -> Option<(bool, bool)> {
        if self.leaving.contains_key(username) {
            return None;
        }
        self.members.get(username).copied()
    }
}

pub type VaultLock = Arc<RwLock<VaultState>>;

#[derive(Default)]
struct Registry {
    vaults: HashMap<String, (VaultLock, Arc<Summary>)>,
    /// Vaults being created, by creator, and their ids.
    creating: HashMap<String, u32>,
    creating_ids: HashSet<String>,
    /// Each user's current identity's fingerprint (base64).
    identities: HashMap<String, String>,
}

pub struct SharedVaults {
    vaults_dir: PathBuf,
    users_dir: PathBuf,
    bundles_dir: PathBuf,
    registry: Mutex<Registry>,
    /// Held while changing identities and while checking a record's members'
    /// identities until it's stored, so neither sees the other half done.
    pub identity_lock: tokio::sync::Mutex<()>,
}

async fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .await?;
    fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).await
}

/// Writes `data` to a temporary file, flushes it and renames it over `path`.
pub async fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(path.file_name().unwrap_or_default());
    tmp_name.push(".tmp");
    let tmp_path = path.with_file_name(tmp_name);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp_path)
        .await?;
    f.write_all(data).await?;
    f.sync_all().await?;
    drop(f);
    fs::rename(&tmp_path, path).await
}

async fn read_optional(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    match fs::read(path).await {
        Ok(data) => Ok(Some(data)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

async fn remove_optional(path: &Path) -> std::io::Result<()> {
    match fs::remove_file(path).await {
        Err(e) if e.kind() != ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Ids are chosen by the creating browser: 32 lowercase hex digits.
pub fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn parse_version(wire: &[u8]) -> anyhow::Result<VersionBody> {
    let frames = sharing::decode_frames(wire, 4)?;
    Ok(serde_json::from_slice(frames[0])?)
}

use sharing::fingerprint_hex;

fn record_fingerprints(record: &RecordBody) -> Vec<String> {
    record
        .members
        .iter()
        .map(|m| m.fingerprint.clone())
        .collect()
}

/// A creation in progress, counted against its creator until it's dropped.
pub struct CreationReservation<'a> {
    shared: &'a SharedVaults,
    creator: String,
    id: String,
}

impl Drop for CreationReservation<'_> {
    fn drop(&mut self) {
        let mut registry = self.shared.registry();
        registry.creating_ids.remove(&self.id);
        if let Some(n) = registry.creating.get_mut(&self.creator) {
            *n -= 1;
            if *n == 0 {
                registry.creating.remove(&self.creator);
            }
        }
    }
}

pub enum ReserveError {
    Exists,
    TooMany(u32),
}

impl SharedVaults {
    /// Loads the shared vaults kept in `dir` (`server_data/.shared`, which no
    /// username can collide with since usernames can't start with '.').
    pub async fn load(dir: &Path) -> anyhow::Result<Self> {
        let vaults_dir = dir.join("vaults");
        let identities_dir = dir.join("identities");
        let users_dir = identities_dir.join("users");
        let bundles_dir = identities_dir.join("bundles");
        for d in [dir, &vaults_dir, &identities_dir, &users_dir, &bundles_dir] {
            create_private_dir(d).await?;
        }
        let shared = Self {
            vaults_dir,
            users_dir,
            bundles_dir,
            registry: Mutex::new(Registry::default()),
            identity_lock: tokio::sync::Mutex::new(()),
        };
        let mut registry = Registry::default();
        let mut entries = fs::read_dir(&shared.vaults_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let Some(id) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if !valid_id(&id) {
                continue;
            }
            match shared.load_vault(&id).await {
                Ok(Some(state)) => {
                    let summary = Arc::new(state.summary());
                    registry
                        .vaults
                        .insert(id, (Arc::new(RwLock::new(state)), summary));
                }
                Ok(None) => {}
                Err(e) => anyhow::bail!("error loading shared vault {id}: {e:?}"),
            }
        }
        let mut entries = fs::read_dir(&shared.users_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let Some(username) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if username.starts_with('.') {
                continue;
            }
            let bundle = fs::read(entry.path()).await?;
            registry.identities.insert(
                username,
                sharing::b64_encode(&sharing::fingerprint(&bundle)),
            );
        }
        *shared.registry() = registry;
        Ok(shared)
    }

    fn registry(&self) -> MutexGuard<'_, Registry> {
        // only ever changed in whole steps, so it's consistent even if a
        // holder panicked
        self.registry.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn vault_dir(&self, id: &str) -> PathBuf {
        self.vaults_dir.join(id)
    }

    pub fn record_path(&self, id: &str, seq: u64) -> PathBuf {
        self.vault_dir(id).join("records").join(seq.to_string())
    }

    pub fn current_path(&self, id: &str) -> PathBuf {
        self.vault_dir(id).join("current")
    }

    /// Where a new epoch's first version waits while the epoch is started
    /// (see `start_epoch`).
    fn next_path(&self, id: &str) -> PathBuf {
        self.vault_dir(id).join("next")
    }

    pub fn archive_path(&self, id: &str, epoch: u64) -> PathBuf {
        self.vault_dir(id).join("archive").join(epoch.to_string())
    }

    /// The seqs of the records kept, in order.
    async fn record_seqs(&self, id: &str) -> std::io::Result<Vec<u64>> {
        let mut seqs = Vec::new();
        let mut entries = match fs::read_dir(self.vault_dir(id).join("records")).await {
            Ok(o) => o,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(seqs),
            Err(e) => return Err(e),
        };
        while let Some(entry) = entries.next_entry().await? {
            if let Some(seq) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<u64>().ok())
            {
                seqs.push(seq);
            }
        }
        seqs.sort_unstable();
        Ok(seqs)
    }

    /// Loads a vault, finishing or undoing an epoch change interrupted by a
    /// crash. `None` if its creation never finished.
    async fn load_vault(&self, id: &str) -> anyhow::Result<Option<VaultState>> {
        let dir = self.vault_dir(id);
        let Some(meta) = read_optional(&dir.join("meta.json")).await? else {
            return Ok(None);
        };
        let meta: VaultMeta = serde_json::from_slice(&meta)?;
        let mut seqs = self.record_seqs(id).await?;
        let Some(&(mut seq)) = seqs.last() else {
            return Ok(None);
        };
        let mut current = fs::read(self.current_path(id)).await?;
        let mut version = parse_version(&current)?;
        if version.epoch != seq {
            match read_optional(&self.next_path(id)).await? {
                // the record and the new epoch's first version were saved:
                // finish switching to them
                Some(next) if parse_version(&next)?.epoch == seq => {
                    self.archive(id, version.epoch, &current).await?;
                    fs::rename(self.next_path(id), self.current_path(id)).await?;
                    current = next;
                    version = parse_version(&current)?;
                }
                // only the record was: drop it
                _ => {
                    fs::remove_file(self.record_path(id, seq)).await?;
                    seqs.pop();
                    seq -= 1;
                }
            }
        }
        // left over from a crash just before an epoch's record was saved
        remove_optional(&self.next_path(id)).await?;
        let record_wire = fs::read(self.record_path(id, seq)).await?;
        let record = sharing::parse_record(&record_wire)?;
        let first_seq = seqs.first().copied().unwrap_or(seq);
        let mut record_fps = BTreeMap::new();
        for &s in &seqs {
            let wire = fs::read(self.record_path(id, s)).await?;
            record_fps.insert(s, record_fingerprints(&sharing::parse_record(&wire)?));
        }
        let mut archives = BTreeMap::new();
        if let Ok(mut entries) = fs::read_dir(dir.join("archive")).await {
            while let Some(entry) = entries.next_entry().await? {
                let Some(epoch) = entry
                    .file_name()
                    .to_str()
                    .and_then(|n| n.parse::<u64>().ok())
                else {
                    continue;
                };
                if epoch < first_seq {
                    // its record was dropped (a crash while pruning)
                    remove_optional(&entry.path()).await?;
                    continue;
                }
                let wire = fs::read(entry.path()).await?;
                archives.insert(
                    epoch,
                    ArchiveInfo {
                        len: wire.len() as u64,
                        content_len: sharing::archive_content_len(&wire)?,
                    },
                );
            }
        }
        Ok(Some(VaultState {
            meta,
            record,
            record_wire,
            first_seq,
            record_fingerprints: record_fps,
            version,
            version_len: current.len() as u64,
            version_content_len: sharing::version_content_len(&current)?,
            archives,
            deleted: false,
        }))
    }

    // ── The registry ─────────────────────────────────────────────────────────

    pub fn lookup(&self, id: &str) -> Option<(VaultLock, Arc<Summary>)> {
        self.registry().vaults.get(id).cloned()
    }

    /// The vaults `username` is a member of (and hasn't left).
    pub fn summaries_for(&self, username: &str) -> Vec<(String, Arc<Summary>)> {
        self.registry()
            .vaults
            .iter()
            .filter(|(_, (_, s))| s.member(username).is_some())
            .map(|(id, (_, s))| (id.clone(), s.clone()))
            .collect()
    }

    /// Whether `username` is in any vault's latest member list (even if
    /// leaving), so their identity is in use.
    pub fn in_any_vault(&self, username: &str) -> bool {
        self.registry()
            .vaults
            .values()
            .any(|(_, s)| s.members.contains_key(username))
    }

    /// Records a vault's change; call while holding its lock.
    pub fn update_summary(&self, id: &str, state: &VaultState) {
        if let Some(entry) = self.registry().vaults.get_mut(id) {
            entry.1 = Arc::new(state.summary());
        }
    }

    /// Counts a vault being created against its creator, if they may create
    /// one more (`max`: how many they may have; `None` for no limit).
    pub fn reserve_creation(
        &self,
        id: &str,
        creator: &str,
        max: Option<u32>,
    ) -> Result<CreationReservation<'_>, ReserveError> {
        let mut registry = self.registry();
        if registry.vaults.contains_key(id) || registry.creating_ids.contains(id) {
            return Err(ReserveError::Exists);
        }
        if let Some(max) = max {
            let existing = registry
                .vaults
                .values()
                .filter(|(_, s)| s.creator == creator)
                .count() as u32;
            let pending = registry.creating.get(creator).copied().unwrap_or(0);
            if existing + pending >= max {
                return Err(ReserveError::TooMany(max));
            }
        }
        *registry.creating.entry(creator.to_string()).or_default() += 1;
        registry.creating_ids.insert(id.to_string());
        Ok(CreationReservation {
            shared: self,
            creator: creator.to_string(),
            id: id.to_string(),
        })
    }

    // ── Changing vaults ──────────────────────────────────────────────────────

    pub async fn save_meta(&self, id: &str, meta: &VaultMeta) -> anyhow::Result<()> {
        write_atomic(
            &self.vault_dir(id).join("meta.json"),
            &serde_json::to_vec(meta)?,
        )
        .await?;
        Ok(())
    }

    /// Stores a new vault's first record and version and registers it (the
    /// reservation ends with it). The vault exists once `meta.json` is
    /// written, last.
    pub async fn create(
        &self,
        reservation: CreationReservation<'_>,
        meta: VaultMeta,
        record: RecordBody,
        record_wire: &[u8],
        version: VersionBody,
        version_wire: &[u8],
    ) -> anyhow::Result<()> {
        let id = reservation.id.clone();
        let dir = self.vault_dir(&id);
        let result: anyhow::Result<()> = async {
            create_private_dir(&dir).await?;
            create_private_dir(&dir.join("records")).await?;
            create_private_dir(&dir.join("archive")).await?;
            write_atomic(&self.record_path(&id, 0), record_wire).await?;
            write_atomic(&self.current_path(&id), version_wire).await?;
            self.save_meta(&id, &meta).await
        }
        .await;
        if let Err(e) = result {
            let _ = fs::remove_dir_all(&dir).await;
            return Err(e);
        }
        let state = VaultState {
            meta,
            first_seq: 0,
            record_fingerprints: BTreeMap::from([(0, record_fingerprints(&record))]),
            record,
            record_wire: record_wire.to_vec(),
            version,
            version_len: version_wire.len() as u64,
            version_content_len: sharing::version_content_len(version_wire)?,
            archives: BTreeMap::new(),
            deleted: false,
        };
        let summary = Arc::new(state.summary());
        let mut registry = self.registry();
        registry
            .vaults
            .insert(id, (Arc::new(RwLock::new(state)), summary));
        drop(registry);
        drop(reservation);
        Ok(())
    }

    async fn archive(
        &self,
        id: &str,
        epoch: u64,
        version_wire: &[u8],
    ) -> anyhow::Result<ArchiveInfo> {
        let archive = sharing::archive_of_version(version_wire)?;
        write_atomic(&self.archive_path(id, epoch), &archive).await?;
        Ok(ArchiveInfo {
            len: archive.len() as u64,
            content_len: sharing::archive_content_len(&archive)?,
        })
    }

    /// Starts a new epoch: stores its record, archives the current version's
    /// history and makes `version_wire` (the epoch's first version) current.
    /// The steps are ordered so `load_vault` can finish or undo them after a
    /// crash. Updates `state` (but not its records' pruning).
    pub async fn start_epoch(
        &self,
        id: &str,
        state: &mut VaultState,
        record: RecordBody,
        record_wire: &[u8],
        version: VersionBody,
        version_wire: &[u8],
    ) -> anyhow::Result<()> {
        write_atomic(&self.next_path(id), version_wire).await?;
        write_atomic(&self.record_path(id, record.seq), record_wire).await?;
        let current = fs::read(self.current_path(id)).await?;
        let archived = self.archive(id, state.version.epoch, &current).await?;
        fs::rename(self.next_path(id), self.current_path(id)).await?;
        state.archives.insert(state.version.epoch, archived);
        state
            .record_fingerprints
            .insert(record.seq, record_fingerprints(&record));
        state.record = record;
        state.record_wire = record_wire.to_vec();
        state.version = version;
        state.version_len = version_wire.len() as u64;
        state.version_content_len = sharing::version_content_len(version_wire)?;
        Ok(())
    }

    /// Replaces the current version (of the same epoch).
    pub async fn save_version(
        &self,
        id: &str,
        state: &mut VaultState,
        version: VersionBody,
        version_wire: &[u8],
    ) -> anyhow::Result<()> {
        let content_len = sharing::version_content_len(version_wire)?;
        write_atomic(&self.current_path(id), version_wire).await?;
        state.version = version;
        state.version_len = version_wire.len() as u64;
        state.version_content_len = content_len;
        Ok(())
    }

    /// Drops the oldest records beyond the vault's limit, with their epochs'
    /// archives, then the oldest archives until the vault fits its size
    /// limit. Returns the fingerprints no longer named in any record kept.
    pub async fn prune(&self, id: &str, state: &mut VaultState) -> Vec<String> {
        let max_records = state.meta.limits.max_records.max(1) as u64;
        let mut dropped_fps = Vec::new();
        while state.record.seq + 1 - state.first_seq > max_records {
            let seq = state.first_seq;
            if let Err(e) = remove_optional(&self.archive_path(id, seq)).await {
                eprintln!("Error occured attempting to remove an archive\n  e={e:?}");
                break;
            }
            state.archives.remove(&seq);
            if let Err(e) = remove_optional(&self.record_path(id, seq)).await {
                eprintln!("Error occured attempting to remove a record\n  e={e:?}");
                break;
            }
            dropped_fps.extend(state.record_fingerprints.remove(&seq).unwrap_or_default());
            state.first_seq += 1;
        }
        while state.usage() > state.meta.limits.max_data_size {
            let Some((&epoch, _)) = state.archives.iter().next() else {
                break;
            };
            if let Err(e) = remove_optional(&self.archive_path(id, epoch)).await {
                eprintln!("Error occured attempting to remove an archive\n  e={e:?}");
                break;
            }
            state.archives.remove(&epoch);
        }
        let kept: HashSet<&String> = state.record_fingerprints.values().flatten().collect();
        dropped_fps.retain(|fp| !kept.contains(fp));
        dropped_fps
    }

    /// Deletes a vault: its `meta.json` first, so a crash midway leaves files
    /// that aren't loaded. Call while holding its lock; it's then marked
    /// deleted and unregistered. Returns the fingerprints its records named.
    pub async fn delete(&self, id: &str, state: &mut VaultState) -> std::io::Result<Vec<String>> {
        let dir = self.vault_dir(id);
        fs::remove_file(dir.join("meta.json")).await?;
        self.registry().vaults.remove(id);
        state.deleted = true;
        if let Err(e) = fs::remove_dir_all(&dir).await {
            eprintln!("Error occured attempting to remove a deleted vault's files\n  e={e:?}");
        }
        Ok(state
            .record_fingerprints
            .values()
            .flatten()
            .cloned()
            .collect())
    }

    // ── Identities ───────────────────────────────────────────────────────────

    /// `username` must have been validated (see `validate_username`).
    pub async fn read_identity(&self, username: &str) -> std::io::Result<Option<Vec<u8>>> {
        read_optional(&self.users_dir.join(username)).await
    }

    /// Publishes `username`'s identity (call holding `identity_lock`).
    /// Returns the replaced one's fingerprint, if any.
    pub async fn write_identity(
        &self,
        username: &str,
        bundle: &[u8],
    ) -> std::io::Result<Option<String>> {
        let fingerprint = sharing::b64_encode(&sharing::fingerprint(bundle));
        let hex = fingerprint_hex(&fingerprint).unwrap_or_default();
        write_atomic(&self.bundles_dir.join(hex), bundle).await?;
        write_atomic(&self.users_dir.join(username), bundle).await?;
        Ok(self
            .registry()
            .identities
            .insert(username.to_string(), fingerprint))
    }

    /// A bundle still kept, by its fingerprint (64 hex digits).
    pub async fn read_identity_by_fingerprint(
        &self,
        fingerprint_hex: &str,
    ) -> std::io::Result<Option<Vec<u8>>> {
        if fingerprint_hex.len() != 64 || !fingerprint_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(None);
        }
        read_optional(&self.bundles_dir.join(fingerprint_hex.to_ascii_lowercase())).await
    }

    /// A bundle by its fingerprint as records name it (base64).
    pub async fn bundle_of(&self, fingerprint: &str) -> std::io::Result<Option<Vec<u8>>> {
        match fingerprint_hex(fingerprint) {
            Some(hex) => self.read_identity_by_fingerprint(&hex).await,
            None => Ok(None),
        }
    }

    /// Deletes the bundles of these fingerprints that are no longer anyone's
    /// identity nor named in any record kept. Call holding `identity_lock`.
    pub async fn forget_bundles(&self, fingerprints: impl IntoIterator<Item = String>) {
        let unused: Vec<String> = {
            let registry = self.registry();
            fingerprints
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .filter(|fp| {
                    !registry.identities.values().any(|f| f == fp)
                        && !registry
                            .vaults
                            .values()
                            .any(|(_, s)| s.fingerprints.contains(fp))
                })
                .collect()
        };
        for fp in unused {
            if let Some(hex) = fingerprint_hex(&fp)
                && let Err(e) = remove_optional(&self.bundles_dir.join(hex)).await
            {
                eprintln!("Error occured attempting to remove an identity bundle\n  e={e:?}");
            }
        }
    }
}
