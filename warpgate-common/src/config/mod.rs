mod defaults;
mod target;

use std::path::PathBuf;
use std::time::Duration;

use defaults::*;
use poem_openapi::Object;
use serde::{Deserialize, Serialize};
pub use target::*;
use url::Url;
use uuid::Uuid;
use warpgate_sso::SsoProviderConfig;

use crate::auth::CredentialKind;
use crate::helpers::otp::OtpSecretKey;
use crate::{ListenEndpoint, Secret, WarpgateError};

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

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Hash, Object)]
pub struct Role {
    #[serde(default)]
    pub id: Uuid,
    pub name: String,
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

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Default)]
pub enum ConfigProviderKind {
    #[serde(rename = "file")]
    #[default]
    File,
    #[serde(rename = "database")]
    Database,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WarpgateConfigStore {
    #[serde(default)]
    pub targets: Vec<Target>,

    #[serde(default)]
    pub users: Vec<User>,

    #[serde(default)]
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

    #[serde(default)]
    pub config_provider: ConfigProviderKind,
}

impl Default for WarpgateConfigStore {
    fn default() -> Self {
        Self {
            targets: vec![],
            users: vec![],
            roles: vec![],
            sso_providers: vec![],
            recordings: <_>::default(),
            external_host: None,
            database_url: _default_database_url(),
            ssh: <_>::default(),
            http: <_>::default(),
            mysql: <_>::default(),
            log: <_>::default(),
            config_provider: <_>::default(),
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
