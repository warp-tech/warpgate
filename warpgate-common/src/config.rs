use serde::Deserialize;

fn _default_port() -> u16 {
    22
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

#[derive(Debug, Deserialize)]
#[allow(unused)]
pub struct WarpgateConfig {
    pub targets: Vec<Target>,
    pub users: Vec<User>,
    pub roles: Vec<Role>,
    pub recordings_path: String,
    pub database_url: String,
}
