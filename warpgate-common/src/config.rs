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
}

#[derive(Debug, Deserialize, Clone)]
#[allow(unused)]
#[serde(tag = "type")]
pub enum UserAuth {
    #[serde(rename = "password")]
    Password {
        password: String,
    },
    #[serde(rename = "publickey")]
    PublicKey {
        key: String,
    },
}

#[derive(Debug, Deserialize, Clone)]
#[allow(unused)]
pub struct User {
    pub username: String,
    pub auth: UserAuth,
}

#[derive(Debug, Deserialize)]
#[allow(unused)]
pub struct WarpgateConfig {
    pub targets: Vec<Target>,
    pub users: Vec<User>,
    pub recordings_path: String,
    pub database_url: String,
}
