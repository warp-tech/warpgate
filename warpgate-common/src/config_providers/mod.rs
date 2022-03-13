mod file;
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
pub use file::FileConfigProvider;
use uuid::Uuid;

use crate::{TargetSnapshot, TicketSnapshot, UserSnapshot};

pub enum AuthResult {
    Accepted {
        username: String,
        via_ticket: Option<TicketSnapshot>,
    },
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
    async fn list_users(&mut self) -> Result<Vec<UserSnapshot>>;

    async fn list_targets(&mut self) -> Result<Vec<TargetSnapshot>>;

    async fn authorize(
        &mut self,
        selector: &str,
        credentials: &[AuthCredential],
    ) -> Result<AuthResult>;

    async fn authorize_target(&mut self, username: &str, target: &str) -> Result<bool>;

    async fn consume_ticket(&mut self, ticket_id: &Uuid) -> Result<()>;
}
