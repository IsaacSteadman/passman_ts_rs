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
    /// How many shared vaults may be created under this policy (none unless
    /// set, so existing policies don't gain storage they weren't given).
    #[serde(default)]
    max_shared_vaults: u32,
    #[serde(default)]
    num_shared_vaults: u32,
    /// The size limit of each shared vault created under this policy;
    /// `MaxDataSize` when not set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "tsbindings", ts(optional, type = "number"))]
    max_shared_vault_data_size: Option<u64>,
    /// How many members each of those shared vaults may have (unlimited when
    /// not set, up to the server's `MAX_SHARED_VAULT_MEMBERS`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "tsbindings", ts(optional))]
    max_shared_vault_members: Option<u32>,
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

/// The limits of one shared vault: those of the policy it was created under,
/// whichever credentials its members use.
pub struct SharedVaultLimits {
    pub max_data_size: Option<u64>,
    pub max_members: Option<u32>,
    /// False once that policy was removed or made a null policy: the vault
    /// can still be read and left, but not changed.
    pub writable: bool,
}

/// A shared vault counted against a policy by `create_shared_vault_hook`;
/// the count is given back on drop unless `commit()` has been called.
pub struct SharedVaultSlot {
    /// The policy the vault is created under (`None` for the server access
    /// password), which sets its limits and is given the count back when the
    /// vault is deleted.
    pub policy_ns: Option<String>,
    rollback: Option<RollbackHandle>,
}

impl SharedVaultSlot {
    pub fn commit(&mut self) {
        if let Some(handle) = &mut self.rollback {
            handle.commit();
        }
    }
}

fn ns_error() -> HttpResponse {
    HttpResponse::BadRequest().json(json!({
        "type": "E_SERVER_NS",
        "params": ["server_ns", "Passman-Server-Pass"],
        "message": "unrecognized server_ns or server_pass"
    }))
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
    /// one more.
    pub async fn create_shared_vault_hook(
        self: Arc<PolicyStorage>,
        params: PolicyParams,
    ) -> Result<SharedVaultSlot, HttpResponse> {
        let Some(ns) = params.server_ns else {
            return if subtle::ConstantTimeEq::ct_eq(
                self.config.server_access_password.as_bytes(),
                params.server_pass.as_bytes(),
            )
            .into()
            {
                Ok(SharedVaultSlot {
                    policy_ns: None,
                    rollback: None,
                })
            } else {
                Err(ns_error())
            };
        };
        let mut writer = self.policies.write().await;
        let Some(PolicyConfig { password, inner }) = writer.get_mut(&ns) else {
            return Err(ns_error());
        };
        if !bool::from(subtle::ConstantTimeEq::ct_eq(
            password.as_bytes(),
            params.server_pass.as_bytes(),
        )) {
            return Err(ns_error());
        }
        let rollback = match inner {
            InnerPolicyConfig::NullPolicy => {
                return Err(policy_error(
                    "create_shared_vault",
                    "null policy".to_string(),
                ));
            }
            InnerPolicyConfig::RootPolicy => None,
            InnerPolicyConfig::LimitedPolicy { data } => {
                if data.num_shared_vaults >= data.max_shared_vaults {
                    return Err(policy_error(
                        "create_shared_vault",
                        format!(
                            "number of shared vaults {} has reached the maximum {}",
                            data.num_shared_vaults, data.max_shared_vaults
                        ),
                    ));
                }
                data.num_shared_vaults += 1;
                self.notify.notify_one();
                Some(RollbackHandle {
                    committed: false,
                    key: ns.clone(),
                    policy_storage: self.clone(),
                    counter: Counter::SharedVaults,
                })
            }
        };
        Ok(SharedVaultSlot {
            policy_ns: Some(ns),
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

    pub async fn shared_vault_limits(&self, policy_ns: Option<&str>) -> SharedVaultLimits {
        const UNLIMITED: SharedVaultLimits = SharedVaultLimits {
            max_data_size: None,
            max_members: None,
            writable: true,
        };
        let Some(ns) = policy_ns else {
            return UNLIMITED;
        };
        match self.policies.read().await.get(ns).map(|p| &p.inner) {
            Some(InnerPolicyConfig::RootPolicy) => UNLIMITED,
            Some(InnerPolicyConfig::LimitedPolicy { data }) => SharedVaultLimits {
                max_data_size: Some(
                    data.max_shared_vault_data_size
                        .unwrap_or(data.max_data_size),
                ),
                max_members: data.max_shared_vault_members,
                writable: true,
            },
            Some(InnerPolicyConfig::NullPolicy) | None => SharedVaultLimits {
                max_data_size: None,
                max_members: None,
                writable: false,
            },
        }
    }

    pub async fn read_account_server_policy_auth(
        &self,
        params: PolicyParams,
    ) -> Result<LenReadChecker, HttpResponse> {
        if let Some(ns) = params.server_ns {
            let reader = self.policies.read().await;
            let PolicyConfig { password, inner } = match reader.get(&ns) {
                None => {
                    return Err(HttpResponse::BadRequest().json(json!({
                        "type": "E_SERVER_NS",
                        "params": ["server_ns", "Passman-Server-Pass"],
                        "message": "unrecognized server_ns or server_pass"
                    })));
                }
                Some(s) => s,
            };
            if subtle::ConstantTimeEq::ct_eq(password.as_bytes(), params.server_pass.as_bytes())
                .into()
            {
                match inner {
                    InnerPolicyConfig::LimitedPolicy { data } => Ok(LenReadChecker::Limited {
                        max_data_size: data.max_data_size,
                    }),
                    InnerPolicyConfig::NullPolicy => Err(HttpResponse::BadRequest().json(json!({
                        "type": "E_POLICY",
                        "action": "read_account",
                        "message": "action was blocked by server policy",
                        "policy_message": "null policy"
                    }))),
                    InnerPolicyConfig::RootPolicy => Ok(LenReadChecker::AlwaysPass),
                }
            } else {
                Err(HttpResponse::BadRequest().json(json!({
                    "type": "E_SERVER_NS",
                    "params": ["server_ns", "Passman-Server-Pass"],
                    "message": "unrecognized server_ns or server_pass"
                })))
            }
        } else if subtle::ConstantTimeEq::ct_eq(
            self.config.server_access_password.as_bytes(),
            params.server_pass.as_bytes(),
        )
        .into()
        {
            Ok(LenReadChecker::AlwaysPass)
        } else {
            Err(HttpResponse::BadRequest().json(json!({
                "type": "E_SERVER_NS",
                "params": ["server_ns", "Passman-Server-Pass"],
                "message": "unrecognized server_ns or server_pass"
            })))
        }
    }

    pub async fn create_account_hook_accum_len_auth(
        self: Arc<PolicyStorage>,
        params: PolicyParams,
    ) -> Result<LenAccumChecker, HttpResponse> {
        if let Some(ns) = params.server_ns {
            let reader = self.policies.read().await;
            let PolicyConfig { password, .. } = match reader.get(&ns) {
                None => {
                    return Err(HttpResponse::BadRequest().json(json!({
                        "type": "E_SERVER_NS",
                        "params": ["server_ns", "Passman-Server-Pass"],
                        "message": "unrecognized server_ns or server_pass"
                    })));
                }
                Some(s) => s,
            };
            if subtle::ConstantTimeEq::ct_eq(password.as_bytes(), params.server_pass.as_bytes())
                .into()
            {
                let mut writer = match self.policies.upgrade(reader).await {
                    Ok(o) => o,
                    Err(_) => {
                        eprintln!("Failed to upgrade reader lock: another upgrade was in progress");
                        return Err(HttpResponse::Conflict().json(json!({
                            "type": "E_POLICY_CONFLICT",
                            "action": "read_account",
                            "message": "action was conflicted, retry recommended"
                        })));
                    }
                };
                let inner = match writer.get_mut(&ns) {
                    None => {
                        return Err(HttpResponse::BadRequest().json(json!({
                            "type": "E_SERVER_NS",
                            "params": ["server_ns", "Passman-Server-Pass"],
                            "message": "unrecognized server_ns or server_pass"
                        })));
                    }
                    Some(s) => &mut s.inner,
                };
                match inner {
                    InnerPolicyConfig::NullPolicy => Err(HttpResponse::BadRequest().json(json!({
                        "type": "E_POLICY",
                        "action": "read_account",
                        "message": "action was blocked by server policy",
                        "policy_message": "null policy"
                    }))),
                    InnerPolicyConfig::RootPolicy => Ok(LenAccumChecker::AlwaysPass),
                    InnerPolicyConfig::LimitedPolicy { data } => {
                        if data.num_accounts >= data.max_accounts {
                            Err(HttpResponse::BadRequest().json(json!({
                                "type": "E_POLICY",
                                "action": "create_account",
                                "message": "action was blocked by server policy",
                                "policy_message": format!(
                                    "number of accounts {} has reached the maximum {}",
                                    data.num_accounts, data.max_accounts
                                )
                            })))
                        } else {
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
            } else {
                Err(HttpResponse::BadRequest().json(json!({
                    "type": "E_SERVER_NS",
                    "params": ["server_ns", "Passman-Server-Pass"],
                    "message": "unrecognized server_ns or server_pass"
                })))
            }
        } else if subtle::ConstantTimeEq::ct_eq(
            self.config.server_access_password.as_bytes(),
            params.server_pass.as_bytes(),
        )
        .into()
        {
            Ok(LenAccumChecker::AlwaysPass)
        } else {
            Err(HttpResponse::BadRequest().json(json!({
                "type": "E_SERVER_NS",
                "params": ["server_ns", "Passman-Server-Pass"],
                "message": "unrecognized server_ns or server_pass"
            })))
        }
    }

    pub async fn update_account_hook_accum_len(
        &self,
        params: PolicyParams,
    ) -> Result<LenAccumChecker, HttpResponse> {
        if let Some(ns) = params.server_ns {
            let reader = self.policies.read().await;
            let PolicyConfig { password, inner } = match reader.get(&ns) {
                None => {
                    return Err(HttpResponse::BadRequest().json(json!({
                        "type": "E_SERVER_NS",
                        "params": ["server_ns", "Passman-Server-Pass"],
                        "message": "unrecognized server_ns or server_pass"
                    })));
                }
                Some(s) => s,
            };
            if subtle::ConstantTimeEq::ct_eq(password.as_bytes(), params.server_pass.as_bytes())
                .into()
            {
                match inner {
                    InnerPolicyConfig::NullPolicy => Err(HttpResponse::BadRequest().json(json!({
                        "type": "E_POLICY",
                        "action": "read_account",
                        "message": "action was blocked by server policy",
                        "policy_message": "null policy"
                    }))),
                    InnerPolicyConfig::RootPolicy => Ok(LenAccumChecker::AlwaysPass),
                    InnerPolicyConfig::LimitedPolicy { data } => Ok(LenAccumChecker::Limited {
                        action: "create_account".to_string(),
                        max_data_size: data.max_data_size,
                        rollback: None,
                    }),
                }
            } else {
                Err(HttpResponse::BadRequest().json(json!({
                    "type": "E_SERVER_NS",
                    "params": ["server_ns", "Passman-Server-Pass"],
                    "message": "unrecognized server_ns or server_pass"
                })))
            }
        } else if subtle::ConstantTimeEq::ct_eq(
            self.config.server_access_password.as_bytes(),
            params.server_pass.as_bytes(),
        )
        .into()
        {
            Ok(LenAccumChecker::AlwaysPass)
        } else {
            Err(HttpResponse::BadRequest().json(json!({
                "type": "E_SERVER_NS",
                "params": ["server_ns", "Passman-Server-Pass"],
                "message": "unrecognized server_ns or server_pass"
            })))
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
