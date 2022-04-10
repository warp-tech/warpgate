mod file;
use crate::{Secret, Target, UserSnapshot};
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
pub use file::FileConfigProvider;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::*;
use uuid::Uuid;
use warpgate_db_entities::Ticket;

pub enum AuthResult {
    Accepted { username: String },
    Rejected,
}

pub enum AuthCredential {
    Password(Secret<String>),
    PublicKey {
        kind: String,
        public_key_bytes: Bytes,
    },
}

#[async_trait]
pub trait ConfigProvider {
    async fn list_users(&mut self) -> Result<Vec<UserSnapshot>>;

    async fn list_targets(&mut self) -> Result<Vec<Target>>;

    async fn authorize(
        &mut self,
        username: &str,
        credentials: &[AuthCredential],
    ) -> Result<AuthResult>;

    async fn authorize_target(&mut self, username: &str, target: &str) -> Result<bool>;

    async fn consume_ticket(&mut self, ticket_id: &Uuid) -> Result<()>;
}

//TODO: move this somewhere
pub async fn authorize_ticket(
    db: &Arc<Mutex<DatabaseConnection>>,
    secret: &Secret<String>,
) -> Result<Option<Ticket::Model>> {
    let ticket = {
        let db = db.lock().await;
        Ticket::Entity::find()
            .filter(Ticket::Column::Secret.eq(&secret.expose_secret()[..]))
            .one(&*db)
            .await?
    };
    match ticket {
        Some(ticket) => {
            if let Some(0) = ticket.uses_left {
                warn!("Ticket is used up: {}", &ticket.id);
                return Ok(None);
            }

            if let Some(datetime) = ticket.expiry {
                if datetime < chrono::Utc::now() {
                    warn!("Ticket has expired: {}", &ticket.id);
                    return Ok(None);
                }
            }

            Ok(Some(ticket))
        }
        None => {
            warn!("Ticket not found: {}", &secret.expose_secret());
            Ok(None)
        }
    }
}
