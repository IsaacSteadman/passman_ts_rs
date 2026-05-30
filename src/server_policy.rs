use crate::{config::ServerConfig, ur_dw_lock::UrDwLock};
use actix_web::HttpResponse;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::HashMap, path::Path, sync::Arc};
use tokio::{fs, sync::Notify, task::JoinHandle};

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

/// Held by a `LenAccumChecker` that was produced by a create-account hook.
/// Decrements `num_accounts` in the policy file on drop unless `commit()` has
/// been called, ensuring the increment is rolled back when the overall
/// operation fails.  At most two disk writes occur: one for the increment and
/// one for the compensating decrement.
pub struct RollbackHandle {
    committed: bool,
    policy_storage: Arc<PolicyStorage>,
    key: String,
}

impl RollbackHandle {
    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for RollbackHandle {
    fn drop(&mut self) {
        if !self.committed {
            return;
        }
        let storage = self.policy_storage.clone();
        let key = std::mem::take(&mut self.key);
        tokio::spawn(async move {
            match storage.policies.write().await {
                Err(e) => {
                    eprintln!("Failed to acquire policy write lock for rollback: {}", e);
                }
                Ok(mut writer) => {
                    if let Some(PolicyConfig {
                        inner: InnerPolicyConfig::LimitedPolicy { data, .. },
                        ..
                    }) = writer.get_mut(&key)
                    {
                        if let Some(new_num_accounts) = data.num_accounts.checked_sub(1) {
                            data.num_accounts = new_num_accounts;
                            storage.notify.notify_waiters();
                        }
                    }
                }
            }
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

// ── Storage ──────────────────────────────────────────────────────────────────

type Policies = HashMap<String, PolicyConfig>;

pub struct PolicyStorage {
    policies: UrDwLock<Policies>,
    notify: Notify,
    config: ServerConfig,
}

#[derive(Debug, Deserialize)]
pub struct PolicyParams {
    pub server_pass: String,
    pub server_ns: Option<String>,
}

pub enum GetPolicyErr {
    ConflictRetryRecommended,
    ServerPolicyNotFound,
    ServerPolicyBadPassword,
}

impl PolicyStorage {
    pub async fn new(
        base_dir: &Path,
        config: ServerConfig,
    ) -> anyhow::Result<(Arc<Self>, JoinHandle<anyhow::Result<()>>)> {
        let server_policy_path = base_dir.join("policies.json");
        let vec_u8: Vec<u8> = match fs::read(&server_policy_path).await {
            Ok(o) => o,
            Err(e) => {
                anyhow::bail!("error reading {server_policy_path:?}: {e:?}");
            }
        };
        let res = Arc::new(Self {
            policies: UrDwLock::new(match serde_json::from_slice(&vec_u8) {
                Ok(o) => o,
                Err(e) => {
                    anyhow::bail!("error parsing {server_policy_path:?}: {e:?}");
                }
            }),
            notify: Notify::new(),
            config,
        });
        let aself = res.clone();
        Ok((
            res,
            tokio::spawn(async move {
                loop {
                    aself.notify.notified().await;
                    fs::write("./policies.json", {
                        let reader = aself.policies.read().await?;
                        if aself.config.pretty_policies_json.is_some() {
                            serde_json::to_vec_pretty(reader.as_ref())?
                        } else {
                            serde_json::to_vec(reader.as_ref())?
                        }
                    })
                    .await?;
                }
            }),
        ))
    }

    pub async fn read_account_server_policy_auth(
        &self,
        params: PolicyParams,
    ) -> Result<LenReadChecker, HttpResponse> {
        if let Some(ns) = params.server_ns {
            let reader = match self.policies.read().await {
                Ok(o) => o,
                _ => {
                    return Err(HttpResponse::Conflict().json(json!({
                        "type": "E_POLICY_CONFLICT",
                        "action": "read_account",
                        "message": "action was conflicted, retry recommended"
                    })));
                }
            };
            let PolicyConfig { password, inner } = match reader.get(&ns) {
                None => {
                    return Err(HttpResponse::BadRequest().json(json!({
                        "type": "E_SERVER_NS",
                        "query_params": ["server_ns", "server_pass"],
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
                return Err(HttpResponse::BadRequest().json(json!({
                    "type": "E_SERVER_NS",
                    "query_params": ["server_ns", "server_pass"],
                    "message": "unrecognized server_ns or server_pass"
                })));
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
                "query_params": ["server_ns", "server_pass"],
                "message": "unrecognized server_ns or server_pass"
            })))
        }
    }

    pub async fn create_account_hook_accum_len_auth(
        self: Arc<PolicyStorage>,
        params: PolicyParams,
    ) -> Result<LenAccumChecker, HttpResponse> {
        if let Some(ns) = params.server_ns {
            let reader = match self.policies.read().await {
                Ok(o) => o,
                _ => {
                    return Err(HttpResponse::Conflict().json(json!({
                        "type": "E_POLICY_CONFLICT",
                        "action": "read_account",
                        "message": "action was conflicted, retry recommended"
                    })));
                }
            };
            let PolicyConfig { password, .. } = match reader.get(&ns) {
                None => {
                    return Err(HttpResponse::BadRequest().json(json!({
                        "type": "E_SERVER_NS",
                        "query_params": ["server_ns", "server_pass"],
                        "message": "unrecognized server_ns or server_pass"
                    })));
                }
                Some(s) => s,
            };
            if subtle::ConstantTimeEq::ct_eq(password.as_bytes(), params.server_pass.as_bytes())
                .into()
            {
                let mut writer = match reader.upgrade().await {
                    Ok(o) => o,
                    Err((ue, _)) => {
                        eprintln!("Failed to upgrade reader lock: {ue:?}");
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
                            "query_params": ["server_ns", "server_pass"],
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
                            self.notify.notify_waiters();

                            Ok(LenAccumChecker::Limited {
                                action: "create_account".to_string(),
                                max_data_size: data.max_data_size,
                                rollback: Some(RollbackHandle {
                                    committed: false,
                                    key: ns.clone(),
                                    policy_storage: self.clone(),
                                }),
                            })
                        }
                    }
                }
            } else {
                return Err(HttpResponse::BadRequest().json(json!({
                    "type": "E_SERVER_NS",
                    "query_params": ["server_ns", "server_pass"],
                    "message": "unrecognized server_ns or server_pass"
                })));
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
                "query_params": ["server_ns", "server_pass"],
                "message": "unrecognized server_ns or server_pass"
            })))
        }
    }

    pub async fn update_account_hook_accum_len(
        &self,
        params: PolicyParams,
    ) -> Result<LenAccumChecker, HttpResponse> {
        if let Some(ns) = params.server_ns {
            let reader = match self.policies.read().await {
                Ok(o) => o,
                _ => {
                    return Err(HttpResponse::Conflict().json(json!({
                        "type": "E_POLICY_CONFLICT",
                        "action": "read_account",
                        "message": "action was conflicted, retry recommended"
                    })));
                }
            };
            let PolicyConfig { password, inner } = match reader.get(&ns) {
                None => {
                    return Err(HttpResponse::BadRequest().json(json!({
                        "type": "E_SERVER_NS",
                        "query_params": ["server_ns", "server_pass"],
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
                return Err(HttpResponse::BadRequest().json(json!({
                    "type": "E_SERVER_NS",
                    "query_params": ["server_ns", "server_pass"],
                    "message": "unrecognized server_ns or server_pass"
                })));
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
                "query_params": ["server_ns", "server_pass"],
                "message": "unrecognized server_ns or server_pass"
            })))
        }
    }
}
