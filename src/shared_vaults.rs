//! Storage of shared vaults (see `passman_crypto::sharing` for what is in
//! them). The server can't read them, and checks every record and version it
//! stores the same way members' browsers do, so it doesn't store anything a
//! member would refuse.
//!
//! Each vault is a directory in `server_data/.shared/vaults/<id>/`:
//! - `meta.json`: the policy it was created under and members leaving it
//! - `records/<seq>`: its member list records
//! - `current`: its current version
//! - `archive/<epoch>`: the last version of each past epoch without its
//!   tables, for reading that epoch's history
//!
//! Users' identity bundles are in `server_data/.shared/identities/<username>`.

use passman_crypto::sharing::{self, RecordBody, VersionBody};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    io::ErrorKind,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{fs, io::AsyncWriteExt, sync::RwLock};

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct VaultMeta {
    /// The policy the vault was created under: its limits apply to the vault,
    /// and it gets its count back when the vault is deleted.
    pub policy_ns: Option<String>,
    /// Members who left: they can no longer open the vault, and the next
    /// record (made by a manager's browser) must remove them.
    pub leaving: BTreeSet<String>,
}

/// What the server keeps in memory about a vault; the lock around it is held
/// while reading (shared) or changing (exclusive) its files.
pub struct VaultState {
    pub meta: VaultMeta,
    /// The latest record.
    pub record: RecordBody,
    pub record_wire: Vec<u8>,
    /// The current version's body and size.
    pub version: VersionBody,
    pub version_len: u64,
    /// Sizes of the archived versions, by epoch.
    pub archives: BTreeMap<u64, u64>,
}

impl VaultState {
    pub fn is_member(&self, username: &str) -> bool {
        self.record.member(username).is_some() && !self.meta.leaving.contains(username)
    }

    pub fn total_len(&self) -> u64 {
        self.version_len + self.archives.values().sum::<u64>()
    }
}

pub struct SharedVaults {
    vaults_dir: PathBuf,
    identities_dir: PathBuf,
    pub vaults: RwLock<HashMap<String, Arc<RwLock<VaultState>>>>,
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

/// Ids are chosen by the creating browser: 32 lowercase hex digits.
pub fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn parse_version(wire: &[u8]) -> anyhow::Result<VersionBody> {
    let frames = sharing::decode_frames(wire, 4)?;
    Ok(serde_json::from_slice(frames[0])?)
}

impl SharedVaults {
    /// Loads the shared vaults kept in `dir` (`server_data/.shared`, which no
    /// username can collide with since usernames can't start with '.').
    pub async fn load(dir: &Path) -> anyhow::Result<Self> {
        let vaults_dir = dir.join("vaults");
        let identities_dir = dir.join("identities");
        create_private_dir(dir).await?;
        create_private_dir(&vaults_dir).await?;
        create_private_dir(&identities_dir).await?;
        let shared = Self {
            vaults_dir,
            identities_dir,
            vaults: RwLock::new(HashMap::new()),
        };
        let mut vaults = HashMap::new();
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
                    vaults.insert(id, Arc::new(RwLock::new(state)));
                }
                Ok(None) => {}
                Err(e) => anyhow::bail!("error loading shared vault {id}: {e:?}"),
            }
        }
        *shared.vaults.write().await = vaults;
        Ok(shared)
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

    async fn latest_seq(&self, id: &str) -> std::io::Result<Option<u64>> {
        let mut latest = None;
        let mut entries = match fs::read_dir(self.vault_dir(id).join("records")).await {
            Ok(o) => o,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        while let Some(entry) = entries.next_entry().await? {
            if let Some(seq) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<u64>().ok())
            {
                latest = latest.max(Some(seq));
            }
        }
        Ok(latest)
    }

    /// Loads a vault, finishing or undoing an epoch change interrupted by a
    /// crash. `None` if its creation never finished.
    async fn load_vault(&self, id: &str) -> anyhow::Result<Option<VaultState>> {
        let dir = self.vault_dir(id);
        let Some(meta) = read_optional(&dir.join("meta.json")).await? else {
            return Ok(None);
        };
        let meta: VaultMeta = serde_json::from_slice(&meta)?;
        let Some(mut seq) = self.latest_seq(id).await? else {
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
                    seq -= 1;
                }
            }
        }
        // left over from a crash just before an epoch's record was saved
        if let Err(e) = fs::remove_file(self.next_path(id)).await
            && e.kind() != ErrorKind::NotFound
        {
            return Err(e.into());
        }
        let record_wire = fs::read(self.record_path(id, seq)).await?;
        let record = sharing::parse_record(&record_wire)?;
        let mut archives = BTreeMap::new();
        if let Ok(mut entries) = fs::read_dir(dir.join("archive")).await {
            while let Some(entry) = entries.next_entry().await? {
                if let Some(epoch) = entry.file_name().to_str().and_then(|n| n.parse().ok()) {
                    archives.insert(epoch, entry.metadata().await?.len());
                }
            }
        }
        Ok(Some(VaultState {
            meta,
            record,
            record_wire,
            version,
            version_len: current.len() as u64,
            archives,
        }))
    }

    pub async fn save_meta(&self, id: &str, meta: &VaultMeta) -> anyhow::Result<()> {
        write_atomic(
            &self.vault_dir(id).join("meta.json"),
            &serde_json::to_vec(meta)?,
        )
        .await?;
        Ok(())
    }

    /// Stores a new vault's first record and version. The vault exists once
    /// `meta.json` is written, last.
    pub async fn create(
        &self,
        id: &str,
        meta: &VaultMeta,
        record_wire: &[u8],
        version_wire: &[u8],
    ) -> anyhow::Result<()> {
        let dir = self.vault_dir(id);
        create_private_dir(&dir).await?;
        create_private_dir(&dir.join("records")).await?;
        create_private_dir(&dir.join("archive")).await?;
        write_atomic(&self.record_path(id, 0), record_wire).await?;
        write_atomic(&self.current_path(id), version_wire).await?;
        self.save_meta(id, meta).await
    }

    async fn archive(&self, id: &str, epoch: u64, version_wire: &[u8]) -> anyhow::Result<u64> {
        let archive = sharing::archive_of_version(version_wire)?;
        write_atomic(&self.archive_path(id, epoch), &archive).await?;
        Ok(archive.len() as u64)
    }

    /// Starts a new epoch: stores its record, archives the current version's
    /// history and makes `version_wire` (the epoch's first version) current.
    /// The steps are ordered so `load_vault` can finish or undo them after a
    /// crash. Returns the archive's size.
    pub async fn start_epoch(
        &self,
        id: &str,
        state: &VaultState,
        record_wire: &[u8],
        version_wire: &[u8],
    ) -> anyhow::Result<u64> {
        write_atomic(&self.next_path(id), version_wire).await?;
        write_atomic(&self.record_path(id, state.record.seq + 1), record_wire).await?;
        let current = fs::read(self.current_path(id)).await?;
        let archived = self.archive(id, state.version.epoch, &current).await?;
        fs::rename(self.next_path(id), self.current_path(id)).await?;
        Ok(archived)
    }

    pub async fn remove_archive(&self, id: &str, epoch: u64) -> std::io::Result<()> {
        fs::remove_file(self.archive_path(id, epoch)).await
    }

    /// Deletes a vault: its `meta.json` first, so a crash midway leaves files
    /// that aren't loaded.
    pub async fn delete(&self, id: &str) -> std::io::Result<()> {
        let dir = self.vault_dir(id);
        fs::remove_file(dir.join("meta.json")).await?;
        fs::remove_dir_all(dir).await
    }

    /// `username` must have been validated (see `validate_username`).
    pub async fn read_identity(&self, username: &str) -> std::io::Result<Option<Vec<u8>>> {
        read_optional(&self.identities_dir.join(username)).await
    }

    /// `username` must have been validated (see `validate_username`). Every
    /// bundle is also kept by its fingerprint, since old records and versions
    /// are checked with the bundle their author had then.
    pub async fn write_identity(&self, username: &str, bundle: &[u8]) -> std::io::Result<()> {
        let by_fingerprint = self.identities_dir.join("by-fingerprint");
        create_private_dir(&by_fingerprint).await?;
        let fingerprint = sharing::fingerprint(bundle)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        write_atomic(&by_fingerprint.join(fingerprint), bundle).await?;
        write_atomic(&self.identities_dir.join(username), bundle).await
    }

    /// Any bundle ever published, by its fingerprint (64 hex digits).
    pub async fn read_identity_by_fingerprint(
        &self,
        fingerprint_hex: &str,
    ) -> std::io::Result<Option<Vec<u8>>> {
        if fingerprint_hex.len() != 64 || !fingerprint_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(None);
        }
        read_optional(
            &self
                .identities_dir
                .join("by-fingerprint")
                .join(fingerprint_hex.to_ascii_lowercase()),
        )
        .await
    }
}
