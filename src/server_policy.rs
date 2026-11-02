use crate::config::ServerConfig;
use actix_web::HttpResponse;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    fs,
    io::AsyncWriteExt,
    sync::{Notify, RwLock},
    task::JoinHandle,
};

// ── On-disk data types (unchanged) ──────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
#[cfg_attr(feature = "tsbindings", derive(ts_rs::TS))]
#[cfg_attr(feature = "tsbindings", ts(export))]
pub struct LimitPolicyData {
    max_accounts: u32,
    num_accounts: u32,
    #[cfg_attr(feature = "tsbindings", ts(type = "number"))]
    max_data_size: u64,
    /// How many shared vaults may exist under this policy in all (no limit
    /// but each user's when not set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "tsbindings", ts(optional))]
    max_shared_vaults: Option<u32>,
    #[serde(default)]
    num_shared_vaults: u32,
    /// How many shared vaults each user may create under this policy
    /// (`DEFAULT_SHARED_VAULTS_PER_USER` when not set). A vault counts
    /// against its creator until it's deleted, even if they leave it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "tsbindings", ts(optional))]
    max_shared_vaults_per_user: Option<u32>,
    /// The size limit of each shared vault created under this policy: its
    /// encrypted contents (tables and history, including past epochs'),
    /// not the signatures around them (`DEFAULT_SHARED_VAULT_DATA_SIZE`
    /// when not set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "tsbindings", ts(optional, type = "number"))]
    max_shared_vault_data_size: Option<u64>,
    /// How many members each of those shared vaults may have
    /// (`DEFAULT_SHARED_VAULT_MEMBERS` when not set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "tsbindings", ts(optional))]
    max_shared_vault_members: Option<u32>,
    /// How many member list records each of those vaults keeps; older ones,
    /// and the history of their epochs, are dropped
    /// (`DEFAULT_SHARED_VAULT_RECORDS` when not set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "tsbindings", ts(optional))]
    max_shared_vault_records: Option<u32>,
}

pub const DEFAULT_SHARED_VAULTS_PER_USER: u32 = 4;
pub const DEFAULT_SHARED_VAULT_DATA_SIZE: u64 = 16 * 1024;
pub const DEFAULT_SHARED_VAULT_MEMBERS: u32 = 8;
pub const DEFAULT_SHARED_VAULT_RECORDS: u32 = 16;
/// The most any shared vault can have, whatever the policy (also the limits
/// of vaults created with the server access password or a root policy).
pub const HARD_MAX_SHARED_VAULT_DATA_SIZE: u64 = 64 * 1024 * 1024;
pub const HARD_MAX_SHARED_VAULT_MEMBERS: u32 = passman_crypto::sharing::MAX_MEMBERS as u32;
pub const HARD_MAX_SHARED_VAULT_RECORDS: u32 = 64;

/// A shared vault's limits, set from its policy when it's created and kept
/// with it, so later policy changes don't shrink it under its contents.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VaultLimits {
    pub max_data_size: u64,
    pub max_members: u32,
    pub max_records: u32,
}

impl VaultLimits {
    pub const HARD_MAX: VaultLimits = VaultLimits {
        max_data_size: HARD_MAX_SHARED_VAULT_DATA_SIZE,
        max_members: HARD_MAX_SHARED_VAULT_MEMBERS,
        max_records: HARD_MAX_SHARED_VAULT_RECORDS,
    };

    fn of_policy(data: &LimitPolicyData) -> Self {
        Self {
            max_data_size: data
                .max_shared_vault_data_size
                .unwrap_or(DEFAULT_SHARED_VAULT_DATA_SIZE)
                .min(HARD_MAX_SHARED_VAULT_DATA_SIZE),
            max_members: data
                .max_shared_vault_members
                .unwrap_or(DEFAULT_SHARED_VAULT_MEMBERS)
                .clamp(1, HARD_MAX_SHARED_VAULT_MEMBERS),
            max_records: data
                .max_shared_vault_records
                .unwrap_or(DEFAULT_SHARED_VAULT_RECORDS)
                .clamp(1, HARD_MAX_SHARED_VAULT_RECORDS),
        }
    }
}

impl LimitPolicyData {
    fn counter_mut(&mut self, counter: Counter) -> &mut u32 {
        match counter {
            Counter::Accounts => &mut self.num_accounts,
            Counter::SharedVaults => &mut self.num_shared_vaults,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
#[cfg_attr(feature = "tsbindings", derive(ts_rs::TS))]
#[cfg_attr(feature = "tsbindings", ts(export))]
pub struct PolicyConfig {
    password: String,
    #[serde(flatten)]
    inner: InnerPolicyConfig,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "PolicyType")]
#[cfg_attr(feature = "tsbindings", derive(ts_rs::TS))]
#[cfg_attr(feature = "tsbindings", ts(export))]
pub enum InnerPolicyConfig {
    RootPolicy,
    NullPolicy,
    LimitedPolicy {
        #[serde(flatten)]
        data: LimitPolicyData,
    },
}

// ── Runtime types ────────────────────────────────────────────────────────────

/// A count of things created under a limited policy.
#[derive(Clone, Copy)]
enum Counter {
    Accounts,
    SharedVaults,
}

/// Held by a `LenAccumChecker` that was produced by a create-account hook (or
/// a `SharedVaultSlot`). Decrements its counter in the policy file on drop
/// unless `commit()` has been called, ensuring the increment is rolled back
/// when the overall operation fails.  At most two disk writes occur: one for
/// the increment and one for the compensating decrement.
pub struct RollbackHandle {
    committed: bool,
    policy_storage: Arc<PolicyStorage>,
    key: String,
    counter: Counter,
}

impl RollbackHandle {
    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for RollbackHandle {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let storage = self.policy_storage.clone();
        let key = std::mem::take(&mut self.key);
        let counter = self.counter;
        tokio::spawn(async move {
            storage.decrement(&key, counter).await;
        });
    }
}

pub enum LenAccumChecker {
    AlwaysPass,
    Limited {
        action: String,
        max_data_size: u64,
        /// `Some` when produced by a create-account hook (rolls back on drop
        /// unless committed); `None` when produced by an update-account hook.
        rollback: Option<RollbackHandle>,
    },
}

impl LenAccumChecker {
    pub async fn check_len(&mut self, total_len: u64) -> Result<(), HttpResponse> {
        match self {
            Self::AlwaysPass => Ok(()),
            Self::Limited {
                action,
                max_data_size,
                ..
            } => {
                if total_len > *max_data_size {
                    Err(HttpResponse::BadRequest().json(json!({
                        "type": "E_POLICY",
                        "action": action,
                        "message": "action was blocked by server policy",
                        "policy_message": format!(
                            "user data size {} is larger than max data size {}",
                            total_len, max_data_size
                        )
                    })))
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Call this when the overall operation succeeds to prevent the rollback
    /// decrement that would otherwise happen on drop.
    pub fn commit(&mut self) {
        if let Self::Limited {
            rollback: Some(handle),
            ..
        } = self
        {
            handle.commit();
        }
    }
}

pub enum LenReadChecker {
    Limited { max_data_size: u64 },
    AlwaysPass,
}

impl LenReadChecker {
    pub fn check_len(&self, total_len: u64) -> Result<(), HttpResponse> {
        match self {
            Self::AlwaysPass => Ok(()),
            Self::Limited { max_data_size } => {
                if total_len > *max_data_size {
                    Err(HttpResponse::BadRequest().json(json!({
                        "type": "E_POLICY",
                        "action": "read_account",
                        "message": "action was blocked by server policy",
                        "policy_message": format!(
                            "user data size {total_len} is larger than max data size {max_data_size}",
                        )
                    })))
                } else {
                    Ok(())
                }
            }
        }
    }
}

/// A shared vault counted against a policy by `create_shared_vault_hook`;
/// the count is given back on drop unless `commit()` has been called.
pub struct SharedVaultSlot {
    /// The policy the vault is created under (`None` for the server access
    /// password), which sets its limits and is given the count back when the
    /// vault is deleted.
    pub policy_ns: Option<String>,
    /// The new vault's limits.
    pub limits: VaultLimits,
    /// How many shared vaults its creator may have created (`None`: no
    /// limit).
    pub max_per_user: Option<u32>,
    rollback: Option<RollbackHandle>,
}

impl SharedVaultSlot {
    pub fn commit(&mut self) {
        if let Some(handle) = &mut self.rollback {
            handle.commit();
        }
    }
}

/// A wrong server or policy password (counted against the client's IP).
fn ns_error() -> HttpResponse {
    let mut response = HttpResponse::BadRequest().json(json!({
        "type": "E_SERVER_NS",
        "params": ["server_ns", "Passman-Server-Pass"],
        "message": "unrecognized server_ns or server_pass"
    }));
    response
        .extensions_mut()
        .insert(crate::rate_limit::ServerPassRejected);
    response
}

fn passwords_match(expected: &str, given: &str) -> bool {
    subtle::ConstantTimeEq::ct_eq(expected.as_bytes(), given.as_bytes()).into()
}

fn policy_error(action: &str, policy_message: String) -> HttpResponse {
    HttpResponse::BadRequest().json(json!({
        "type": "E_POLICY",
        "action": action,
        "message": "action was blocked by server policy",
        "policy_message": policy_message
    }))
}

// ── Storage ──────────────────────────────────────────────────────────────────

type Policies = HashMap<String, PolicyConfig>;

pub struct PolicyStorage {
    policies: RwLock<Policies>,
    /// Wakes the save task; `notify_one` keeps a permit if the task is busy
    /// saving, so a change made during a save is not lost.
    notify: Notify,
    config: ServerConfig,
    path: PathBuf,
}

/// Built by `routes::base::policy_params`; deliberately not `Debug` so the
/// server password can't end up in a log line.
pub struct PolicyParams {
    pub server_pass: String,
    pub server_ns: Option<String>,
}

impl PolicyStorage {
    pub async fn new(
        base_dir: &Path,
        config: ServerConfig,
    ) -> anyhow::Result<(Arc<Self>, JoinHandle<()>)> {
        let server_policy_path = base_dir.join("policies.json");
        let vec_u8: Vec<u8> = match fs::read(&server_policy_path).await {
            Ok(o) => o,
            Err(e) => {
                anyhow::bail!("error reading {server_policy_path:?}: {e:?}");
            }
        };
        let res = Arc::new(Self {
            policies: RwLock::new(match serde_json::from_slice(&vec_u8) {
                Ok(o) => o,
                Err(e) => {
                    anyhow::bail!("error parsing {server_policy_path:?}: {e:?}");
                }
            }),
            notify: Notify::new(),
            config,
            path: server_policy_path,
        });
        let aself = res.clone();
        Ok((
            res,
            tokio::spawn(async move {
                loop {
                    aself.notify.notified().await;
                    if let Err(e) = aself.save().await {
                        eprintln!("Error occured attempting to save policies\n  e={e:?}");
                    }
                }
            }),
        ))
    }

    /// Writes the policies to a temporary file, flushes it to disk, then
    /// renames it over `policies.json`, so a crash mid-save leaves the old
    /// file intact.
    pub async fn save(&self) -> anyhow::Result<()> {
        let data = {
            let reader = self.policies.read().await;
            if self.config.pretty_policies_json.is_some() {
                serde_json::to_vec_pretty(&*reader)?
            } else {
                serde_json::to_vec(&*reader)?
            }
        };
        let tmp_path = self.path.with_extension("json.tmp");
        // policy passwords are in this file, so keep it private to the service account
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)
            .await?;
        f.write_all(&data).await?;
        f.sync_all().await?;
        drop(f);
        fs::rename(&tmp_path, &self.path).await?;
        Ok(())
    }

    /// Gives back one of `counter` taken under the limited policy `key`.
    async fn decrement(&self, key: &str, counter: Counter) {
        let mut writer = self.policies.write().await;
        if let Some(PolicyConfig {
            inner: InnerPolicyConfig::LimitedPolicy { data, .. },
            ..
        }) = writer.get_mut(key)
        {
            let count = data.counter_mut(counter);
            if let Some(new_count) = count.checked_sub(1) {
                *count = new_count;
                self.notify.notify_one();
            }
        }
    }

    /// Counts a new shared vault against the request's policy, if it allows
    /// one more, and returns the vault's limits.
    pub async fn create_shared_vault_hook(
        self: Arc<PolicyStorage>,
        params: PolicyParams,
    ) -> Result<SharedVaultSlot, HttpResponse> {
        let Some(ns) = params.server_ns else {
            return if passwords_match(&self.config.server_access_password, &params.server_pass) {
                Ok(SharedVaultSlot {
                    policy_ns: None,
                    limits: VaultLimits::HARD_MAX,
                    max_per_user: None,
                    rollback: None,
                })
            } else {
                Err(ns_error())
            };
        };
        // no await while holding it, so it's never held for long
        let mut writer = self.policies.write().await;
        let Some(PolicyConfig { password, inner }) = writer.get_mut(&ns) else {
            return Err(ns_error());
        };
        if !passwords_match(password, &params.server_pass) {
            return Err(ns_error());
        }
        let (limits, max_per_user, rollback) = match inner {
            InnerPolicyConfig::NullPolicy => {
                return Err(policy_error(
                    "create_shared_vault",
                    "null policy".to_string(),
                ));
            }
            InnerPolicyConfig::RootPolicy => (VaultLimits::HARD_MAX, None, None),
            InnerPolicyConfig::LimitedPolicy { data } => {
                if let Some(max) = data.max_shared_vaults
                    && data.num_shared_vaults >= max
                {
                    return Err(policy_error(
                        "create_shared_vault",
                        format!(
                            "number of shared vaults {} has reached the maximum {max}",
                            data.num_shared_vaults
                        ),
                    ));
                }
                data.num_shared_vaults += 1;
                self.notify.notify_one();
                (
                    VaultLimits::of_policy(data),
                    Some(
                        data.max_shared_vaults_per_user
                            .unwrap_or(DEFAULT_SHARED_VAULTS_PER_USER),
                    ),
                    Some(RollbackHandle {
                        committed: false,
                        key: ns.clone(),
                        policy_storage: self.clone(),
                        counter: Counter::SharedVaults,
                    }),
                )
            }
        };
        Ok(SharedVaultSlot {
            policy_ns: Some(ns),
            limits,
            max_per_user,
            rollback,
        })
    }

    /// Gives the policy a deleted shared vault was created under its count
    /// back.
    pub async fn release_shared_vault(&self, policy_ns: Option<&str>) {
        if let Some(ns) = policy_ns {
            self.decrement(ns, Counter::SharedVaults).await;
        }
    }

    /// False once the policy a shared vault was created under was removed or
    /// made a null policy: the vault can still be read and left, but not
    /// changed.
    pub async fn shared_vault_writable(&self, policy_ns: Option<&str>) -> bool {
        let Some(ns) = policy_ns else {
            return true;
        };
        matches!(
            self.policies.read().await.get(ns).map(|p| &p.inner),
            Some(InnerPolicyConfig::RootPolicy | InnerPolicyConfig::LimitedPolicy { .. })
        )
    }

    pub async fn read_account_server_policy_auth(
        &self,
        params: PolicyParams,
    ) -> Result<LenReadChecker, HttpResponse> {
        let Some(ns) = params.server_ns else {
            return if passwords_match(&self.config.server_access_password, &params.server_pass) {
                Ok(LenReadChecker::AlwaysPass)
            } else {
                Err(ns_error())
            };
        };
        let reader = self.policies.read().await;
        let Some(PolicyConfig { password, inner }) = reader.get(&ns) else {
            return Err(ns_error());
        };
        if !passwords_match(password, &params.server_pass) {
            return Err(ns_error());
        }
        match inner {
            InnerPolicyConfig::LimitedPolicy { data } => Ok(LenReadChecker::Limited {
                max_data_size: data.max_data_size,
            }),
            InnerPolicyConfig::NullPolicy => {
                Err(policy_error("read_account", "null policy".to_string()))
            }
            InnerPolicyConfig::RootPolicy => Ok(LenReadChecker::AlwaysPass),
        }
    }

    pub async fn create_account_hook_accum_len_auth(
        self: Arc<PolicyStorage>,
        params: PolicyParams,
    ) -> Result<LenAccumChecker, HttpResponse> {
        let Some(ns) = params.server_ns else {
            return if passwords_match(&self.config.server_access_password, &params.server_pass) {
                Ok(LenAccumChecker::AlwaysPass)
            } else {
                Err(ns_error())
            };
        };
        // no await while holding it, so it's never held for long
        let mut writer = self.policies.write().await;
        let Some(PolicyConfig { password, inner }) = writer.get_mut(&ns) else {
            return Err(ns_error());
        };
        if !passwords_match(password, &params.server_pass) {
            return Err(ns_error());
        }
        match inner {
            InnerPolicyConfig::NullPolicy => {
                Err(policy_error("create_account", "null policy".to_string()))
            }
            InnerPolicyConfig::RootPolicy => Ok(LenAccumChecker::AlwaysPass),
            InnerPolicyConfig::LimitedPolicy { data } => {
                if data.num_accounts >= data.max_accounts {
                    return Err(policy_error(
                        "create_account",
                        format!(
                            "number of accounts {} has reached the maximum {}",
                            data.num_accounts, data.max_accounts
                        ),
                    ));
                }
                data.num_accounts += 1;
                self.notify.notify_one();
                Ok(LenAccumChecker::Limited {
                    action: "create_account".to_string(),
                    max_data_size: data.max_data_size,
                    rollback: Some(RollbackHandle {
                        committed: false,
                        key: ns.clone(),
                        policy_storage: self.clone(),
                        counter: Counter::Accounts,
                    }),
                })
            }
        }
    }

    pub async fn update_account_hook_accum_len(
        &self,
        params: PolicyParams,
    ) -> Result<LenAccumChecker, HttpResponse> {
        let Some(ns) = params.server_ns else {
            return if passwords_match(&self.config.server_access_password, &params.server_pass) {
                Ok(LenAccumChecker::AlwaysPass)
            } else {
                Err(ns_error())
            };
        };
        let reader = self.policies.read().await;
        let Some(PolicyConfig { password, inner }) = reader.get(&ns) else {
            return Err(ns_error());
        };
        if !passwords_match(password, &params.server_pass) {
            return Err(ns_error());
        }
        match inner {
            InnerPolicyConfig::NullPolicy => {
                Err(policy_error("update_account", "null policy".to_string()))
            }
            InnerPolicyConfig::RootPolicy => Ok(LenAccumChecker::AlwaysPass),
            InnerPolicyConfig::LimitedPolicy { data } => Ok(LenAccumChecker::Limited {
                action: "update_account".to_string(),
                max_data_size: data.max_data_size,
                rollback: None,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn limited_storage(dir: &Path) -> Arc<PolicyStorage> {
        std::fs::write(
            dir.join("policies.json"),
            r#"{"ns":{"Password":"pw","PolicyType":"LIMITED_POLICY","MaxAccounts":1,"NumAccounts":0,"MaxDataSize":1024}}"#,
        )
        .unwrap();
        let config = ServerConfig {
            port: 0,
            cors: false,
            debug: false,
            pretty_policies_json: None,
            server_access_password: "root".to_string(),
            rate_limit: Default::default(),
            max_buffered_upload_bytes: 1 << 20,
        };
        PolicyStorage::new(dir, config).await.unwrap().0
    }

    fn ns_params() -> PolicyParams {
        PolicyParams {
            server_pass: "pw".to_string(),
            server_ns: Some("ns".to_string()),
        }
    }

    async fn num_accounts(storage: &PolicyStorage) -> u32 {
        match &storage.policies.read().await["ns"].inner {
            InnerPolicyConfig::LimitedPolicy { data } => data.num_accounts,
            _ => unreachable!(),
        }
    }

    /// Lets the rollback task spawned by `RollbackHandle::drop` run.
    async fn settle() {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn uncommitted_account_creation_is_rolled_back() {
        let dir = tempfile::tempdir().unwrap();
        let storage = limited_storage(dir.path()).await;
        let checker = match storage
            .clone()
            .create_account_hook_accum_len_auth(ns_params())
            .await
        {
            Ok(o) => o,
            Err(_) => panic!("account creation should be allowed"),
        };
        assert_eq!(num_accounts(&storage).await, 1);
        drop(checker);
        settle().await;
        assert_eq!(num_accounts(&storage).await, 0);
    }

    #[tokio::test]
    async fn committed_account_creation_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let storage = limited_storage(dir.path()).await;
        let mut checker = match storage
            .clone()
            .create_account_hook_accum_len_auth(ns_params())
            .await
        {
            Ok(o) => o,
            Err(_) => panic!("account creation should be allowed"),
        };
        checker.commit();
        drop(checker);
        settle().await;
        assert_eq!(num_accounts(&storage).await, 1);
        // MaxAccounts is 1, so the slot is now used up
        assert!(
            storage
                .clone()
                .create_account_hook_accum_len_auth(ns_params())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn policy_changes_are_saved_to_base_dir() {
        let dir = tempfile::tempdir().unwrap();
        let storage = limited_storage(dir.path()).await;
        let mut checker = match storage
            .clone()
            .create_account_hook_accum_len_auth(ns_params())
            .await
        {
            Ok(o) => o,
            Err(_) => panic!("account creation should be allowed"),
        };
        checker.commit();
        let path = dir.path().join("policies.json");
        let saved_num_accounts = || {
            let saved: Policies = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            match &saved["ns"].inner {
                InnerPolicyConfig::LimitedPolicy { data } => data.num_accounts,
                _ => unreachable!(),
            }
        };
        for _ in 0..200 {
            if saved_num_accounts() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(saved_num_accounts(), 1);
        assert!(!dir.path().join("policies.json.tmp").exists());
    }
}
