mod file;
use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
pub use file::FileConfigProvider;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use tokio::sync::Mutex;
use tracing::*;
use uuid::Uuid;
use warpgate_db_entities::Ticket;

use crate::auth::{AuthCredential, CredentialKind, CredentialPolicy};
use crate::{Secret, Target, UserSnapshot, WarpgateError};

#[derive(Debug, Clone)]
pub enum AuthResult {
    Accepted { username: String },
    Need(HashSet<CredentialKind>),
    Rejected,
}

#[async_trait]
pub trait ConfigProvider {
    async fn list_users(&mut self) -> Result<Vec<UserSnapshot>, WarpgateError>;

    async fn list_targets(&mut self) -> Result<Vec<Target>, WarpgateError>;

    async fn validate_credential(
        &mut self,
        username: &str,
        client_credential: &AuthCredential,
    ) -> Result<bool, WarpgateError>;

    async fn username_for_sso_credential(
        &mut self,
        client_credential: &AuthCredential,
    ) -> Result<Option<String>, WarpgateError>;

    async fn get_credential_policy(
        &mut self,
        username: &str,
    ) -> Result<Option<Box<dyn CredentialPolicy + Sync + Send>>, WarpgateError>;

    async fn authorize_target(
        &mut self,
        username: &str,
        target: &str,
    ) -> Result<bool, WarpgateError>;

    async fn consume_ticket(&mut self, ticket_id: &Uuid) -> Result<(), WarpgateError>;
}

//TODO: move this somewhere
pub async fn authorize_ticket(
    db: &Arc<Mutex<DatabaseConnection>>,
    secret: &Secret<String>,
) -> Result<Option<Ticket::Model>, WarpgateError> {
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
