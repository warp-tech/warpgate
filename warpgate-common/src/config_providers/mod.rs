mod file;
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
pub use file::FileConfigProvider;

pub enum AuthResult {
    Accepted,
    Rejected,
}

pub enum AuthCredential {
    Password(String),
    PublicKey {
        kind: String,
        public_key_bytes: Bytes,
    },
}

#[async_trait]
pub trait ConfigProvider {
    async fn authorize_user(
        &mut self,
        username: &str,
        credentials: &Vec<AuthCredential>,
    ) -> Result<AuthResult>;

    async fn authorize_target(
        &mut self,
        username: &str,
        target: &str,
    ) -> Result<bool>;
}
