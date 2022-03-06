mod file;
use anyhow::Result;
use async_trait::async_trait;
pub use file::FileConfigProvider;

pub enum AuthResult {
    Accepted,
    Rejected,
}

pub enum AuthCredential {
    Password(String),
    PublicKey(String),
}

#[async_trait]
pub trait ConfigProvider {
    async fn authorize_user(&mut self, username: &str, credentials: Vec<AuthCredential>) -> Result<AuthResult>;
}
