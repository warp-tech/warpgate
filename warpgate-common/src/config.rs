use poem_openapi::{Object, Union};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use crate::helpers::otp::OtpSecretKey;
use crate::Secret;

const fn _default_true() -> bool {
    true
}

const fn _default_false() -> bool {
    false
}

const fn _default_port() -> u16 {
    22
}

fn _default_username() -> String {
    "root".to_owned()
}

fn _default_empty_string() -> String {
    "".to_owned()
}

fn _default_recordings_path() -> String {
    "./data/recordings".to_owned()
}

fn _default_database_url() -> Secret<String> {
    Secret::new("sqlite:data/db".to_owned())
}

fn _default_http_listen() -> String {
    "0.0.0.0:8888".to_owned()
}

fn _default_retention() -> Duration {
    Duration::SECOND * 60 * 60 * 24 * 7
}

fn _default_empty_string_vec() -> Vec<String> {
    vec![]
}

#[derive(Debug, Deserialize, Serialize, Clone, Object)]
pub struct TargetSSHOptions {
    pub host: String,
    #[serde(default = "_default_port")]
    pub port: u16,
    #[serde(default = "_default_username")]
    pub username: String,
    #[serde(default)]
    #[oai(skip)]
    pub auth: SSHTargetAuth,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
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
    pub headers: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Object, Default)]
pub struct TargetWebAdminOptions {}

#[derive(Debug, Deserialize, Serialize, Clone, Object)]
pub struct Target {
    pub name: String,
    #[serde(default = "_default_empty_string_vec")]
    pub allow_roles: Vec<String>,
    #[serde(flatten)]
    pub options: TargetOptions,
}

#[derive(Debug, Deserialize, Serialize, Clone, Union)]
#[oai(discriminator_name = "kind")]
pub enum TargetOptions {
    #[serde(rename = "ssh")]
    Ssh(TargetSSHOptions),
    #[serde(rename = "http")]
    Http(TargetHTTPOptions),
    #[serde(rename = "web_admin")]
    WebAdmin(TargetWebAdminOptions),
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(tag = "type")]
pub enum UserAuthCredential {
    #[serde(rename = "password")]
    Password { hash: Secret<String> },
    #[serde(rename = "publickey")]
    PublicKey { key: Secret<String> },
    #[serde(rename = "otp")]
    TOTP {
        #[serde(with = "crate::helpers::serde_base64_secret")]
        key: OtpSecretKey,
    },
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct User {
    pub username: String,
    pub credentials: Vec<UserAuthCredential>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require: Option<Vec<String>>,
    pub roles: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Hash)]
pub struct Role {
    pub name: String,
}

fn _default_ssh_listen() -> String {
    "0.0.0.0:2222".to_owned()
}

fn _default_ssh_client_key() -> String {
    "./client_key".to_owned()
}

fn _default_ssh_keys_path() -> String {
    "./data/keys".to_owned()
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SSHConfig {
    #[serde(default = "_default_ssh_listen")]
    pub listen: String,

    #[serde(default = "_default_ssh_keys_path")]
    pub keys: String,

    #[serde(default = "_default_ssh_client_key")]
    pub client_key: String,
}

impl Default for SSHConfig {
    fn default() -> Self {
        SSHConfig {
            listen: _default_ssh_listen(),
            keys: _default_ssh_keys_path(),
            client_key: _default_ssh_client_key(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPConfig {
    #[serde(default = "_default_false")]
    pub enable: bool,

    #[serde(default = "_default_http_listen")]
    pub listen: String,

    #[serde(default)]
    pub certificate: String,

    #[serde(default)]
    pub key: String,
}

impl Default for HTTPConfig {
    fn default() -> Self {
        HTTPConfig {
            enable: true,
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
    pub recordings: RecordingsConfig,

    #[serde(default = "_default_database_url")]
    pub database_url: Secret<String>,

    #[serde(default)]
    pub ssh: SSHConfig,

    #[serde(default)]
    pub http: HTTPConfig,

    #[serde(default)]
    pub log: LogConfig,
}

impl Default for WarpgateConfigStore {
    fn default() -> Self {
        Self {
            targets: vec![],
            users: vec![],
            roles: vec![],
            recordings: RecordingsConfig::default(),
            database_url: _default_database_url(),
            ssh: SSHConfig::default(),
            http: HTTPConfig::default(),
            log: LogConfig::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WarpgateConfig {
    pub store: WarpgateConfigStore,
    pub paths_relative_to: PathBuf,
}
