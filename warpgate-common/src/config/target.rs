use std::collections::HashMap;

use poem_openapi::{Enum, Object, Union};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::defaults::*;
use crate::Secret;

#[derive(Debug, Deserialize, Serialize, Clone, Object)]
pub struct TargetSSHOptions {
    pub host: String,
    #[serde(default = "_default_ssh_port")]
    pub port: u16,
    #[serde(default = "_default_username")]
    pub username: String,
    #[serde(default)]
    pub allow_insecure_algos: Option<bool>,
    #[serde(default)]
    pub auth: SSHTargetAuth,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Union)]
#[serde(untagged)]
#[oai(discriminator_name = "kind", one_of)]
pub enum SSHTargetAuth {
    #[serde(rename = "password")]
    Password(SshTargetPasswordAuth),
    #[serde(rename = "publickey")]
    PublicKey(SshTargetPublicKeyAuth),
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct SshTargetPasswordAuth {
    pub password: Secret<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object, Default)]
pub struct SshTargetPublicKeyAuth {}

impl Default for SSHTargetAuth {
    fn default() -> Self {
        SSHTargetAuth::PublicKey(SshTargetPublicKeyAuth::default())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Object)]
pub struct TargetHTTPOptions {
    #[serde(default = "_default_empty_string")]
    pub url: String,

    #[serde(default)]
    pub tls: Tls,

    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,

    #[serde(default)]
    pub external_host: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Enum, PartialEq, Eq, Default)]
pub enum TlsMode {
    #[serde(rename = "disabled")]
    Disabled,
    #[serde(rename = "preferred")]
    #[default]
    Preferred,
    #[serde(rename = "required")]
    Required,
}

#[derive(Debug, Deserialize, Serialize, Clone, Object)]
pub struct Tls {
    #[serde(default)]
    pub mode: TlsMode,

    #[serde(default = "_default_true")]
    pub verify: bool,
}

#[allow(clippy::derivable_impls)]
impl Default for Tls {
    fn default() -> Self {
        Self {
            mode: TlsMode::default(),
            verify: false,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Object)]
pub struct TargetMySqlOptions {
    #[serde(default = "_default_empty_string")]
    pub host: String,

    #[serde(default = "_default_mysql_port")]
    pub port: u16,

    #[serde(default = "_default_username")]
    pub username: String,

    #[serde(default)]
    pub password: Option<String>,

    #[serde(default)]
    pub tls: Tls,
}

#[derive(Debug, Deserialize, Serialize, Clone, Object, Default)]
pub struct TargetWebAdminOptions {}

#[derive(Debug, Deserialize, Serialize, Clone, Object)]
pub struct Target {
    #[serde(default)]
    pub id: Uuid,
    pub name: String,
    #[serde(default = "_default_empty_vec")]
    pub allow_roles: Vec<String>,
    #[serde(flatten)]
    pub options: TargetOptions,
}

#[derive(Debug, Deserialize, Serialize, Clone, Union)]
#[oai(discriminator_name = "kind", one_of)]
pub enum TargetOptions {
    #[serde(rename = "ssh")]
    Ssh(TargetSSHOptions),
    #[serde(rename = "http")]
    Http(TargetHTTPOptions),
    #[serde(rename = "mysql")]
    MySql(TargetMySqlOptions),
    #[serde(rename = "web_admin")]
    WebAdmin(TargetWebAdminOptions),
}
