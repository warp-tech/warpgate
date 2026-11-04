use poem_openapi::Enum;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use warpgate_tls::TlsMode;

#[derive(Debug, Clone, Copy, Enum)]
pub enum LdapUsernameAttribute {
    Cn,
    Uid,
    Email,
    UserPrincipalName,
    SamAccountName,
}

impl LdapUsernameAttribute {
    pub const fn attribute_name(self) -> &'static str {
        match self {
            Self::Cn => "cn",
            Self::Uid => "uid",
            Self::Email => "mail",
            Self::UserPrincipalName => "userPrincipalName",
            Self::SamAccountName => "sAMAccountName",
        }
    }
}

impl TryFrom<&str> for LdapUsernameAttribute {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(match value {
            "cn" => Self::Cn,
            "uid" => Self::Uid,
            "mail" => Self::Email,
            "userPrincipalName" => Self::UserPrincipalName,
            "sAMAccountName" => Self::SamAccountName,
            _ => return Err(()),
        })
    }
}

#[derive(Clone)]
pub struct LdapConfig {
    pub host: String,
    pub port: u16,
    pub bind_dn: String,
    pub bind_password: String,
    pub tls_mode: TlsMode,
    pub tls_verify: bool,
    pub base_dns: Vec<String>,
    pub user_filter: String,
    pub username_attribute: LdapUsernameAttribute,
    pub ssh_key_attribute: String,
    pub uuid_attribute: Option<String>,
}

impl std::fmt::Debug for LdapConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LdapConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("bind_dn", &self.bind_dn)
            .field("bind_password", &"***")
            .field("tls_mode", &self.tls_mode)
            .field("tls_verify", &self.tls_verify)
            .field("base_dns", &self.base_dns)
            .field("user_filter", &self.user_filter)
            .field("username_attribute", &self.username_attribute)
            .field("ssh_key_attribute", &self.ssh_key_attribute)
            .field("uuid_attribute", &self.uuid_attribute)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapUser {
    pub username: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub dn: String,
    pub object_uuid: Uuid,
    pub ssh_public_keys: Vec<String>,
}
