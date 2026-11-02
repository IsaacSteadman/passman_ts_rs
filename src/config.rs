use crate::rate_limit::RateLimitConfig;
use serde::{Deserialize, Serialize};

/// The port when neither the `PORT` environment variable (which the
/// deployment sets) nor `Port` in config.json gives one.
fn default_port() -> u16 {
    8080
}

fn default_max_buffered_upload_bytes() -> u64 {
    256 * 1024 * 1024
}

#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "tsbindings", derive(ts_rs::TS))]
#[serde(rename_all = "PascalCase")]
#[cfg_attr(feature = "tsbindings", ts(export))]
pub struct ServerConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub cors: bool,
    #[serde(default)]
    pub debug: bool,
    #[serde(default)]
    #[cfg_attr(feature = "tsbindings", ts(optional = nullable))]
    pub pretty_policies_json: Option<u8>,
    pub server_access_password: String,
    /// Request rate limits, and bans and throttling after failed logins.
    #[serde(default)]
    #[cfg_attr(feature = "tsbindings", ts(skip))]
    pub rate_limit: RateLimitConfig,
    /// How many bytes of shared vault uploads may be held in memory at once,
    /// across all requests; uploads beyond that are refused (503) until
    /// others finish.
    #[serde(default = "default_max_buffered_upload_bytes")]
    #[cfg_attr(feature = "tsbindings", ts(type = "number"))]
    pub max_buffered_upload_bytes: u64,
}

impl ServerConfig {
    /// The port to listen on: `PORT` from the environment if set, else
    /// `Port` from config.json.
    pub fn listen_port(&self) -> anyhow::Result<u16> {
        match std::env::var("PORT") {
            Ok(port) => port
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid PORT {port:?}: {e}")),
            Err(_) => Ok(self.port),
        }
    }
}
