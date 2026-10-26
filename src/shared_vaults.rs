//! Shared vaults: vaults that several users can open. As with a user's own
//! vault the server only holds ciphertext. Each shared vault is encrypted with
//! its own random key, which is stored once per member, sealed to that
//! member's sharing key (an X25519 public key, see `passman_crypto::seal`);
//! the matching secret key is kept in the member's own vault.

use crate::routes::base::UserT;
use rand::{TryRngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    io::ErrorKind,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{fs, io::AsyncWriteExt, sync::RwLock};

/// The most members a shared vault can have, whatever its policy allows.
pub const MAX_SHARED_VAULT_MEMBERS: usize = 256;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "tsbindings", derive(ts_rs::TS))]
#[cfg_attr(feature = "tsbindings", ts(export))]
pub enum Role {
    /// Can change the vault, its name and its members, and delete it.
    Owner,
    /// Can change the vault.
    Editor,
}

impl Role {
    pub fn can_write(self) -> bool {
        matches!(self, Role::Owner | Role::Editor)
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Member {
    pub role: Role,
    /// The vault key sealed to this member's sharing key (base64).
    pub wrapped_key: String,
    pub added_by: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SharedVaultMeta {
    /// The policy the vault was created under: its limits apply to the vault,
    /// and it gets its count back when the vault is deleted.
    pub policy_ns: Option<String>,
    /// The vault's name, encrypted with the vault key (base64).
    pub encrypted_name: String,
    pub members: BTreeMap<String, Member>,
}

impl SharedVaultMeta {
    pub fn owner_count(&self) -> usize {
        self.members
            .values()
            .filter(|m| m.role == Role::Owner)
            .count()
    }
}

pub struct SharedVaultEntry {
    pub meta: SharedVaultMeta,
    /// Held while reading or replacing the vault's data file.
    pub data_lock: Arc<RwLock<UserT>>,
}

/// Every shared vault's metadata, kept in memory (and in `vaults/<id>.json`).
/// Lock order: `vaults` before the policies, never the other way round.
pub struct SharedVaults {
    vaults_dir: PathBuf,
    keys_dir: PathBuf,
    pub vaults: RwLock<HashMap<String, SharedVaultEntry>>,
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
async fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
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

impl SharedVaults {
    /// Loads the shared vaults kept in `dir` (`server_data/.shared`, which no
    /// username can collide with since usernames can't start with '.').
    pub async fn load(dir: &Path) -> anyhow::Result<Self> {
        let vaults_dir = dir.join("vaults");
        let keys_dir = dir.join("keys");
        create_private_dir(dir).await?;
        create_private_dir(&vaults_dir).await?;
        create_private_dir(&keys_dir).await?;
        let mut vaults = HashMap::new();
        let mut entries = fs::read_dir(&vaults_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name();
            let Some(id) = name.to_str().and_then(|n| n.strip_suffix(".json")) else {
                continue;
            };
            if !valid_id(id) {
                continue;
            }
            let path = entry.path();
            let meta: SharedVaultMeta = match serde_json::from_slice(&fs::read(&path).await?) {
                Ok(o) => o,
                Err(e) => anyhow::bail!("error parsing {path:?}: {e:?}"),
            };
            vaults.insert(
                id.to_string(),
                SharedVaultEntry {
                    meta,
                    data_lock: Arc::new(RwLock::new(())),
                },
            );
        }
        Ok(Self {
            vaults_dir,
            keys_dir,
            vaults: RwLock::new(vaults),
        })
    }

    pub fn new_id() -> anyhow::Result<String> {
        let mut bytes = [0u8; 16];
        OsRng.try_fill_bytes(&mut bytes)?;
        Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }

    pub fn data_path(&self, id: &str) -> PathBuf {
        self.vaults_dir.join(format!("{id}.vault"))
    }

    /// Where a new version of the data is written before replacing it.
    pub fn write_data_path(&self, id: &str) -> PathBuf {
        self.vaults_dir.join(format!(".{id}.vault.tmp"))
    }

    fn meta_path(&self, id: &str) -> PathBuf {
        self.vaults_dir.join(format!("{id}.json"))
    }

    pub async fn save_meta(&self, id: &str, meta: &SharedVaultMeta) -> anyhow::Result<()> {
        write_atomic(&self.meta_path(id), &serde_json::to_vec(meta)?).await?;
        Ok(())
    }

    /// Creates the (empty) data file of a new vault.
    pub async fn create_data(&self, id: &str) -> std::io::Result<std::fs::Metadata> {
        let f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.data_path(id))
            .await?;
        f.sync_all().await?;
        f.metadata().await
    }

    pub async fn remove_meta(&self, id: &str) -> std::io::Result<()> {
        fs::remove_file(self.meta_path(id)).await
    }

    pub async fn remove_data(&self, id: &str) -> std::io::Result<()> {
        match fs::remove_file(self.data_path(id)).await {
            Err(e) if e.kind() != ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    /// `username` must have been validated (see `validate_username`).
    pub async fn read_sharing_key(&self, username: &str) -> std::io::Result<Option<String>> {
        match fs::read_to_string(self.keys_dir.join(username)).await {
            Ok(key) => Ok(Some(key)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `username` must have been validated (see `validate_username`).
    pub async fn write_sharing_key(&self, username: &str, key: &str) -> std::io::Result<()> {
        write_atomic(&self.keys_dir.join(username), key.as_bytes()).await
    }
}

/// Ids are made by `new_id`: 32 lowercase hex digits.
pub fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
