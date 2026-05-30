use serde::{Deserialize, Serialize};

fn default_port() -> u16 {
    3050
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
}
