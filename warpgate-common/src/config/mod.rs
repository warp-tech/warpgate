use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::time::Duration;

use poem_openapi::{Enum, Object, Union};
use serde::{Deserialize, Serialize};
use url::Url;
use warpgate_sso::SsoProviderConfig;

use crate::auth::CredentialKind;
use crate::helpers::otp::OtpSecretKey;
use crate::{ListenEndpoint, Secret, WarpgateError};

const fn _default_true() -> bool {
    true
}

const fn _default_false() -> bool {
    false
}

const fn _default_ssh_port() -> u16 {
    22
}

const fn _default_mysql_port() -> u16 {
    3306
}

#[inline]
fn _default_username() -> String {
    "root".to_owned()
}

#[inline]
fn _default_empty_string() -> String {
    "".to_owned()
}

#[inline]
fn _default_recordings_path() -> String {
    "./data/recordings".to_owned()
}

#[inline]
fn _default_database_url() -> Secret<String> {
    Secret::new("sqlite:data/db".to_owned())
}

#[inline]
fn _default_http_listen() -> ListenEndpoint {
    #[allow(clippy::unwrap_used)]
    ListenEndpoint("0.0.0.0:8888".to_socket_addrs().unwrap().next().unwrap())
}

#[inline]
fn _default_mysql_listen() -> ListenEndpoint {
    #[allow(clippy::unwrap_used)]
    ListenEndpoint("0.0.0.0:33306".to_socket_addrs().unwrap().next().unwrap())
}

#[inline]
fn _default_retention() -> Duration {
    Duration::SECOND * 60 * 60 * 24 * 7
}

#[inline]
fn _default_empty_vec<T>() -> Vec<T> {
    vec![]
}

#[derive(Debug, Deserialize, Serialize, Clone, Object)]
pub struct TargetSSHOptions {
    pub host: String,
    #[serde(default = "_default_ssh_port")]
    pub port: u16,
    #[serde(default = "_default_username")]
    pub username: String,
    #[serde(default)]
    #[oai(skip)]
    pub auth: SSHTargetAuth,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum SSHTargetAuth {
    #[serde(rename = "password")]
    Password { password: Secret<String> },
    #[serde(rename = "publickey")]
    PublicKey,
}

impl Default for SSHTargetAuth {
    fn default() -> Self {
        SSHTargetAuth::PublicKey
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

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum UserAuthCredential {
    #[serde(rename = "password")]
    Password { hash: Secret<String> },
    #[serde(rename = "publickey")]
    PublicKey { key: Secret<String> },
    #[serde(rename = "otp")]
    Totp {
        #[serde(with = "crate::helpers::serde_base64_secret")]
        key: OtpSecretKey,
    },
    #[serde(rename = "sso")]
    Sso {
        provider: Option<String>,
        email: String,
    },
}

impl UserAuthCredential {
    pub fn kind(&self) -> CredentialKind {
        match self {
            Self::Password { .. } => CredentialKind::Password,
            Self::PublicKey { .. } => CredentialKind::PublicKey,
            Self::Totp { .. } => CredentialKind::Otp,
            Self::Sso { .. } => CredentialKind::Sso,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UserRequireCredentialsPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<Vec<CredentialKind>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh: Option<Vec<CredentialKind>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mysql: Option<Vec<CredentialKind>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct User {
    pub username: String,
    pub credentials: Vec<UserAuthCredential>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require: Option<UserRequireCredentialsPolicy>,
    pub roles: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Hash)]
pub struct Role {
    pub name: String,
}

fn _default_ssh_listen() -> ListenEndpoint {
    #[allow(clippy::unwrap_used)]
    ListenEndpoint("0.0.0.0:2222".to_socket_addrs().unwrap().next().unwrap())
}

fn _default_ssh_keys_path() -> String {
    "./data/keys".to_owned()
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq, Eq, Copy)]
pub enum SshHostKeyVerificationMode {
    #[serde(rename = "prompt")]
    #[default]
    Prompt,
    #[serde(rename = "auto_accept")]
    AutoAccept,
    #[serde(rename = "auto_reject")]
    AutoReject,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SSHConfig {
    #[serde(default = "_default_false")]
    pub enable: bool,

    #[serde(default = "_default_ssh_listen")]
    pub listen: ListenEndpoint,

    #[serde(default = "_default_ssh_keys_path")]
    pub keys: String,

    #[serde(default)]
    pub host_key_verification: SshHostKeyVerificationMode,
}

impl Default for SSHConfig {
    fn default() -> Self {
        SSHConfig {
            enable: false,
            listen: _default_ssh_listen(),
            keys: _default_ssh_keys_path(),
            host_key_verification: Default::default(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPConfig {
    #[serde(default = "_default_false")]
    pub enable: bool,

    #[serde(default = "_default_http_listen")]
    pub listen: ListenEndpoint,

    #[serde(default)]
    pub certificate: String,

    #[serde(default)]
    pub key: String,
}

impl Default for HTTPConfig {
    fn default() -> Self {
        HTTPConfig {
            enable: false,
            listen: _default_http_listen(),
            certificate: "".to_owned(),
            key: "".to_owned(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MySQLConfig {
    #[serde(default = "_default_false")]
    pub enable: bool,

    #[serde(default = "_default_mysql_listen")]
    pub listen: ListenEndpoint,

    #[serde(default)]
    pub certificate: String,

    #[serde(default)]
    pub key: String,
}

impl Default for MySQLConfig {
    fn default() -> Self {
        MySQLConfig {
            enable: false,
            listen: _default_http_listen(),
            certificate: "".to_owned(),
            key: "".to_owned(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RecordingsConfig {
    #[serde(default = "_default_false")]
    pub enable: bool,

    #[serde(default = "_default_recordings_path")]
    pub path: String,
}

impl Default for RecordingsConfig {
    fn default() -> Self {
        Self {
            enable: false,
            path: _default_recordings_path(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LogConfig {
    #[serde(default = "_default_retention", with = "humantime_serde")]
    pub retention: Duration,

    #[serde(default)]
    pub send_to: Option<String>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            retention: _default_retention(),
            send_to: None,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WarpgateConfigStore {
    pub targets: Vec<Target>,
    pub users: Vec<User>,
    pub roles: Vec<Role>,

    #[serde(default)]
    pub sso_providers: Vec<SsoProviderConfig>,

    #[serde(default)]
    pub recordings: RecordingsConfig,

    #[serde(default)]
    pub external_host: Option<String>,

    #[serde(default = "_default_database_url")]
    pub database_url: Secret<String>,

    #[serde(default)]
    pub ssh: SSHConfig,

    #[serde(default)]
    pub http: HTTPConfig,

    #[serde(default)]
    pub mysql: MySQLConfig,

    #[serde(default)]
    pub log: LogConfig,
}

impl Default for WarpgateConfigStore {
    fn default() -> Self {
        Self {
            targets: vec![],
            users: vec![],
            roles: vec![],
            sso_providers: vec![],
            recordings: RecordingsConfig::default(),
            external_host: None,
            database_url: _default_database_url(),
            ssh: SSHConfig::default(),
            http: HTTPConfig::default(),
            mysql: MySQLConfig::default(),
            log: LogConfig::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WarpgateConfig {
    pub store: WarpgateConfigStore,
    pub paths_relative_to: PathBuf,
}

impl WarpgateConfig {
    pub fn construct_external_url(
        &self,
        fallback_host: Option<&str>,
    ) -> Result<Url, WarpgateError> {
        let ext_host = self.store.external_host.as_deref().or(fallback_host);
        let Some(ext_host) = ext_host  else {
          return Err(WarpgateError::ExternalHostNotSet);
        };
        let ext_port = self.store.http.listen.port();

        let mut url = Url::parse(&format!("https://{ext_host}/"))?;

        if ext_port != 443 {
            let _ = url.set_port(Some(ext_port));
        }

        Ok(url)
    }
}
