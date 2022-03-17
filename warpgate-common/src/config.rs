use std::path::PathBuf;

use serde::Deserialize;

fn _default_false() -> bool {
    false
}

fn _default_port() -> u16 {
    22
}

fn _default_recordings_path() -> String {
    "./recordings".to_owned()
}

fn _default_database_url() -> String {
    "sqlite:db".to_owned()
}

fn _default_web_admin_listen() -> String {
    "127.0.0.1:8888".to_owned()
}

#[derive(Debug, Deserialize, Clone)]
#[allow(unused)]
pub struct Target {
    pub name: String,
    pub host: String,
    #[serde(default = "_default_port")]
    pub port: u16,
    pub roles: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[allow(unused)]
#[serde(tag = "type")]
pub enum UserAuthCredential {
    #[serde(rename = "password")]
    Password { password: String },
    #[serde(rename = "publickey")]
    PublicKey { key: String },
}

#[derive(Debug, Deserialize, Clone)]
#[allow(unused)]
pub struct User {
    pub username: String,
    pub credentials: Vec<UserAuthCredential>,
    pub require: Option<Vec<String>>,
    pub roles: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq, Hash)]
#[allow(unused)]
pub struct Role {
    pub name: String,
}

fn _default_ssh_client_key() -> String {
    "./client_key".to_owned()
}

#[derive(Debug, Deserialize, Clone)]
#[allow(unused)]
pub struct SSHConfig {
    pub listen: String,

    #[serde(default = "_default_ssh_client_key")]
    pub client_key: String,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(unused)]
pub struct WebAdminConfig {
    #[serde(default = "_default_false")]
    pub enable: bool,

    #[serde(default = "_default_web_admin_listen")]
    pub listen: String,
}

impl Default for WebAdminConfig {
    fn default() -> Self {
        WebAdminConfig {
            enable: false,
            listen: _default_web_admin_listen(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[allow(unused)]
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

#[derive(Debug, Deserialize, Clone)]
#[allow(unused)]
pub struct WarpgateConfigStore {
    pub targets: Vec<Target>,
    pub users: Vec<User>,
    pub roles: Vec<Role>,

    #[serde(default)]
    pub recordings: RecordingsConfig,

    #[serde(default)]
    pub web_admin: WebAdminConfig,

    #[serde(default = "_default_database_url")]
    pub database_url: String,

    pub ssh: SSHConfig,
}

#[derive(Debug, Clone)]
pub struct WarpgateConfig {
    pub store: WarpgateConfigStore,
    pub paths_relative_to: PathBuf,
}
