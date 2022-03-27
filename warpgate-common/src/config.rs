use poem_openapi::Object;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

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

fn _default_recordings_path() -> String {
    "./data/recordings".to_owned()
}

fn _default_database_url() -> Secret<String> {
    Secret::new("sqlite:data/db".to_owned())
}

fn _default_web_admin_listen() -> String {
    "127.0.0.1:8888".to_owned()
}

fn _default_retention() -> Duration {
    Duration::SECOND * 60 * 60 * 24 * 7
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
pub struct Target {
    pub name: String,
    pub roles: Vec<String>,
    pub ssh: Option<TargetSSHOptions>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(tag = "type")]
pub enum UserAuthCredential {
    #[serde(rename = "password")]
    Password { hash: Secret<String> },
    #[serde(rename = "publickey")]
    PublicKey { key: Secret<String> },
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct User {
    pub username: String,
    pub credentials: Vec<UserAuthCredential>,
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
pub struct WebAdminConfig {
    #[serde(default = "_default_false")]
    pub enable: bool,

    #[serde(default = "_default_web_admin_listen")]
    pub listen: String,
}

impl Default for WebAdminConfig {
    fn default() -> Self {
        WebAdminConfig {
            enable: true,
            listen: _default_web_admin_listen(),
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
pub struct WarpgateConfigStore {
    pub targets: Vec<Target>,
    pub users: Vec<User>,
    pub roles: Vec<Role>,

    #[serde(default)]
    pub recordings: RecordingsConfig,

    #[serde(default)]
    pub web_admin: WebAdminConfig,

    #[serde(default = "_default_database_url")]
    pub database_url: Secret<String>,

    #[serde(default)]
    pub ssh: SSHConfig,

    #[serde(default = "_default_retention", with = "humantime_serde")]
    pub retention: Duration,
}

impl Default for WarpgateConfigStore {
    fn default() -> Self {
        Self {
            targets: vec![],
            users: vec![],
            roles: vec![],
            recordings: RecordingsConfig::default(),
            web_admin: WebAdminConfig::default(),
            database_url: _default_database_url(),
            ssh: SSHConfig::default(),
            retention: _default_retention(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WarpgateConfig {
    pub store: WarpgateConfigStore,
    pub paths_relative_to: PathBuf,
}
