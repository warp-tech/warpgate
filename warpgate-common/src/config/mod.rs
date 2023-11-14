mod defaults;
mod target;

use std::path::PathBuf;
use std::time::Duration;

use defaults::*;
use poem::http;
use poem_openapi::{Object, Union};
use serde::{Deserialize, Serialize};
pub use target::*;
use url::Url;
use uuid::Uuid;
use warpgate_sso::SsoProviderConfig;

use crate::auth::CredentialKind;
use crate::helpers::otp::OtpSecretKey;
use crate::{ListenEndpoint, Secret, WarpgateError};

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Union)]
#[serde(tag = "type")]
#[oai(discriminator_name = "kind", one_of)]
pub enum UserAuthCredential {
    #[serde(rename = "password")]
    Password(UserPasswordCredential),
    #[serde(rename = "publickey")]
    PublicKey(UserPublicKeyCredential),
    #[serde(rename = "otp")]
    Totp(UserTotpCredential),
    #[serde(rename = "sso")]
    Sso(UserSsoCredential),
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct UserPasswordCredential {
    pub hash: Secret<String>,
}
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct UserPublicKeyCredential {
    pub key: Secret<String>,
}
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct UserTotpCredential {
    #[serde(with = "crate::helpers::serde_base64_secret")]
    pub key: OtpSecretKey,
}
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Object)]
pub struct UserSsoCredential {
    pub provider: Option<String>,
    pub email: String,
}

impl UserAuthCredential {
    pub fn kind(&self) -> CredentialKind {
        match self {
            Self::Password(_) => CredentialKind::Password,
            Self::PublicKey(_) => CredentialKind::PublicKey,
            Self::Totp(_) => CredentialKind::Totp,
            Self::Sso(_) => CredentialKind::Sso,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Object, Default)]
pub struct UserRequireCredentialsPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<Vec<CredentialKind>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh: Option<Vec<CredentialKind>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mysql: Option<Vec<CredentialKind>>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Object)]
pub struct User {
    #[serde(default)]
    pub id: Uuid,
    pub username: String,
    pub credentials: Vec<UserAuthCredential>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "require")]
    pub credential_policy: Option<UserRequireCredentialsPolicy>,
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

    #[serde(default)]
    pub trust_x_forwarded_headers: bool,
}

impl Default for HTTPConfig {
    fn default() -> Self {
        HTTPConfig {
            enable: false,
            listen: _default_http_listen(),
            certificate: "".to_owned(),
            key: "".to_owned(),
            trust_x_forwarded_headers: false,
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
            listen: _default_mysql_listen(),
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
    File,
    #[serde(rename = "database")]
    #[default]
    Database,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WarpgateConfigStore {
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<Target>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<User>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
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
        for_request: Option<&poem::Request>,
    ) -> Result<Url, WarpgateError> {
        // if trust x-forwarded, get x-forwarded-host, then try Host, then fallback on external_host
        // if trust x-forwarded, get x-forwarded-proto, then try request scheme, then fallback https
        // if trust x-forwarded, get x-forwarded-port, then try request port, then fallback http listen port
        let trust_forwarded_headers = self.store.http.trust_x_forwarded_headers;
        let url = self.store.external_host.as_ref().map(|x| Url::parse(&format!("https://{}/", x))).and_then(|x| x.ok());
        let (scheme, host, port) = url
            .map_or(
                ("https".to_string(), self.store.external_host.clone(), self.store.http.listen.port()), |
                x| (x.scheme().to_string(), x.host().map(|x| x.to_string()).or(self.store.external_host.clone()), x.port().unwrap_or(self.store.http.listen.port())));

        let (scheme, host, port) = match for_request {
            Some(req) => {
                let scheme = req.uri().scheme().map(|x| x.to_string()).unwrap_or(scheme.clone());
                let host = req.uri().host().map(|x| x.to_string()).or(host);
                let host = req.header(http::header::HOST).map(|x| x.to_string()).or(host);
                let port = req.uri().port_u16().unwrap_or(port);
                match trust_forwarded_headers {
                    true => {
                        let scheme = for_request.and_then(|x| x.header("x-forwarded-proto")).map(|x| x.to_string()).unwrap_or(scheme);
                        let host = for_request.and_then(|x| x.header("x-forwarded-host")).map(|x| x.to_string()).or(host);
                        let port = for_request.and_then(|x| x.header("x-forwarded-port")).and_then(|x| x.parse::<u16>().ok()).unwrap_or(port);
                        (scheme, host, port)
                    },
                    false =>(scheme, host, port)
                }
            },
            None => (scheme, host, port),
        };

        let Some(host) = host else {
            return Err(WarpgateError::ExternalHostNotSet);
        };
        Url::parse(&format!("{}://{}:{}/", scheme, host, port)).map_err(|e| WarpgateError::UrlParse(e))
    }
}
