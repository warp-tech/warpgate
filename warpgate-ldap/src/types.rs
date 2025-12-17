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
    pub fn attribute_name(&self) -> &'static str {
        match self {
            LdapUsernameAttribute::Cn => "cn",
            LdapUsernameAttribute::Uid => "uid",
            LdapUsernameAttribute::Email => "mail",
            LdapUsernameAttribute::UserPrincipalName => "userPrincipalName",
            LdapUsernameAttribute::SamAccountName => "sAMAccountName",
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
    pub username_attribute: LdapUsernameAttribute,
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
