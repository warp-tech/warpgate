use serde::{Deserialize, Serialize};
use uuid::Uuid;
use warpgate_tls::TlsMode;

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
    pub object_uuid: Option<Uuid>,
    pub ssh_public_keys: Vec<String>,
}
