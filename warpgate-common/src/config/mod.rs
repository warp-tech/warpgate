mod defaults;
mod target;

use std::path::PathBuf;
use std::time::Duration;

use defaults::*;
use poem::http::uri;
use poem_openapi::{Object, Union};
use serde::{Deserialize, Serialize};
pub use target::*;
use tracing::warn;
use uri::Scheme;
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postgres: Option<Vec<CredentialKind>>,
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
pub struct SshConfig {
    #[serde(default = "_default_false")]
    pub enable: bool,

    #[serde(default = "_default_ssh_listen")]
    pub listen: ListenEndpoint,

    #[serde(default)]
    pub external_port: Option<u16>,

    #[serde(default = "_default_ssh_keys_path")]
    pub keys: String,

    #[serde(default)]
    pub host_key_verification: SshHostKeyVerificationMode,

    #[serde(default = "_default_ssh_inactivity_timeout", with = "humantime_serde")]
    pub inactivity_timeout: Duration,

    #[serde(default)]
    pub keepalive_interval: Option<Duration>,
}

impl Default for SshConfig {
    fn default() -> Self {
        SshConfig {
            enable: false,
            listen: _default_ssh_listen(),
            keys: _default_ssh_keys_path(),
            host_key_verification: Default::default(),
            external_port: None,
            inactivity_timeout: _default_ssh_inactivity_timeout(),
            keepalive_interval: None,
        }
    }
}

impl SshConfig {
    pub fn external_port(&self) -> u16 {
        self.external_port.unwrap_or(self.listen.port())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HttpConfig {
    #[serde(default = "_default_false")]
    pub enable: bool,

    #[serde(default = "_default_http_listen")]
    pub listen: ListenEndpoint,

    #[serde(default)]
    pub external_port: Option<u16>,

    #[serde(default)]
    pub certificate: String,

    #[serde(default)]
    pub key: String,

    #[serde(default)]
    pub trust_x_forwarded_headers: bool,

    #[serde(default = "_default_session_max_age", with = "humantime_serde")]
    pub session_max_age: Duration,

    #[serde(default = "_default_cookie_max_age", with = "humantime_serde")]
    pub cookie_max_age: Duration,
}

impl Default for HttpConfig {
    fn default() -> Self {
        HttpConfig {
            enable: false,
            listen: _default_http_listen(),
            external_port: None,
            certificate: "".to_owned(),
            key: "".to_owned(),
            trust_x_forwarded_headers: false,
            session_max_age: _default_session_max_age(),
            cookie_max_age: _default_cookie_max_age(),
        }
    }
}

impl HttpConfig {
    pub fn external_port(&self) -> u16 {
        self.external_port.unwrap_or(self.listen.port())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MySqlConfig {
    #[serde(default = "_default_false")]
    pub enable: bool,

    #[serde(default = "_default_mysql_listen")]
    pub listen: ListenEndpoint,

    #[serde(default)]
    pub external_port: Option<u16>,

    #[serde(default)]
    pub certificate: String,

    #[serde(default)]
    pub key: String,
}

impl Default for MySqlConfig {
    fn default() -> Self {
        MySqlConfig {
            enable: false,
            listen: _default_mysql_listen(),
            external_port: None,
            certificate: "".to_owned(),
            key: "".to_owned(),
        }
    }
}

impl MySqlConfig {
    pub fn external_port(&self) -> u16 {
        self.external_port.unwrap_or(self.listen.port())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PostgresConfig {
    #[serde(default = "_default_false")]
    pub enable: bool,

    #[serde(default = "_default_postgres_listen")]
    pub listen: ListenEndpoint,

    #[serde(default)]
    pub external_port: Option<u16>,

    #[serde(default)]
    pub certificate: String,

    #[serde(default)]
    pub key: String,
}

impl Default for PostgresConfig {
    fn default() -> Self {
        PostgresConfig {
            enable: false,
            listen: _default_postgres_listen(),
            external_port: None,
            certificate: "".to_owned(),
            key: "".to_owned(),
        }
    }
}

impl PostgresConfig {
    pub fn external_port(&self) -> u16 {
        self.external_port.unwrap_or(self.listen.port())
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
    pub ssh: SshConfig,

    #[serde(default)]
    pub http: HttpConfig,

    #[serde(default)]
    pub mysql: MySqlConfig,

    #[serde(default)]
    pub postgres: PostgresConfig,

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
            postgres: <_>::default(),
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
    pub fn external_host_from_config(&self) -> Option<(Scheme, String, Option<u16>)> {
        if let Some(external_host) = self.store.external_host.as_ref() {
            #[allow(clippy::unwrap_used)]
            let external_host = external_host.split(":").next().unwrap();

            Some((
                Scheme::HTTPS,
                external_host.to_owned(),
                self.store
                    .http
                    .external_port
                    .or(Some(self.store.http.listen.port())),
            ))
        } else {
            None
        }
    }

    /// Extract external host:port from request headers
    pub fn external_host_from_request(
        &self,
        request: &poem::Request,
    ) -> Option<(Scheme, String, Option<u16>)> {
        let (mut scheme, mut host, mut port) = (Scheme::HTTPS, None, None);
        let trust_forwarded_headers = self.store.http.trust_x_forwarded_headers;

        // Try the Host header first
        scheme = request.uri().scheme().cloned().unwrap_or(scheme);

        let original_url = request.original_uri();
        if let Some(original_host) = original_url.host() {
            host = Some(original_host.to_string());
            port = original_url.port().map(|x| x.as_u16());
        }

        // But prefer X-Forwarded-* headers if enabled
        if trust_forwarded_headers {
            scheme = request
                .header("x-forwarded-proto")
                .and_then(|x| Scheme::try_from(x).ok())
                .unwrap_or(scheme);

            if let Some(xfh) = request.header("x-forwarded-host") {
                // XFH can contain both host and port
                let parts = xfh.split(':').collect::<Vec<_>>();
                host = parts.first().map(|x| x.to_string()).or(host);
                port = parts.get(1).and_then(|x| x.parse::<u16>().ok());
            }

            port = request
                .header("x-forwarded-port")
                .and_then(|x| x.parse::<u16>().ok())
                .or(port);
        }

        host.map(|host| (scheme, host, port))
    }

    pub fn construct_external_url(
        &self,
        for_request: Option<&poem::Request>,
        domain_whitelist: Option<&[String]>,
    ) -> Result<Url, WarpgateError> {
        let Some((scheme, host, port)) = for_request
            .and_then(|r| self.external_host_from_request(r))
            .or(self.external_host_from_config())
        else {
            return Err(WarpgateError::ExternalHostUnknown);
        };

        if let Some(list) = domain_whitelist {
            if !list.contains(&host) {
                return Err(WarpgateError::ExternalHostNotWhitelisted(
                    host.clone(),
                    list.iter().map(|x| x.to_string()).collect(),
                ));
            }
        }

        let mut url = format!("{scheme}://{host}");
        if let Some(port) = port {
            // can't `match` `Scheme`
            if scheme == Scheme::HTTP && port != 80 || scheme == Scheme::HTTPS && port != 443 {
                url = format!("{url}:{port}");
            }
        };
        Url::parse(&url).map_err(WarpgateError::UrlParse)
    }

    pub fn validate(&self) {
        if let Some(ref ext) = self.store.external_host {
            if ext.contains(':') {
                warn!("Looks like your `external_host` config option contains a port - it will be ignored.");
                warn!("Set the external port via the `http.external_port`, `ssh.external_port` or `mysql.external_port` options.");
            }
        }
    }
}
