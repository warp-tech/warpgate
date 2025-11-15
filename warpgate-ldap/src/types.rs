use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TlsMode {
    Disabled,
    Preferred,
    Required,
}

impl From<&str> for TlsMode {
    fn from(s: &str) -> Self {
        match s {
            "disabled" => TlsMode::Disabled,
            "preferred" => TlsMode::Preferred,
            "required" => TlsMode::Required,
            _ => TlsMode::Preferred,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LdapConfig {
    pub host: String,
    pub port: u16,
    pub bind_dn: String,
    pub bind_password: String,
    pub tls_mode: TlsMode,
    pub tls_verify: bool,
    pub base_dns: Vec<String>,
    pub user_filter: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapUser {
    pub username: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub dn: String,
    pub object_uuid: Option<String>,
    pub ssh_public_keys: Vec<String>,
}
