mod db;
use std::sync::Arc;

pub use db::DatabaseConfigProvider;
use enum_dispatch::enum_dispatch;
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::*;
use uuid::Uuid;
use warpgate_common::auth::{AuthCredential, AuthStateUserInfo, CredentialKind, CredentialPolicy};
use warpgate_common::{Secret, Target, User, WarpgateError};
use warpgate_db_entities as e;
use warpgate_sso::SsoProviderConfig;

/// File transfer permission settings for a user-target combination.
/// Used to control SFTP access and track transfer metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTransferPermission {
    /// Whether file uploads (SFTP write) are allowed
    pub upload_allowed: bool,
    /// Whether file downloads (SFTP read) are allowed
    pub download_allowed: bool,
    /// Allowed paths (None = all paths allowed)
    pub allowed_paths: Option<Vec<String>>,
    /// Blocked file extensions (None = no extensions blocked)
    pub blocked_extensions: Option<Vec<String>>,
    /// Maximum file size in bytes (None = no limit)
    pub max_file_size: Option<i64>,
    /// Whether shell/exec/forwarding should be blocked based on instance-wide sftp_permission_mode.
    /// True when mode is "strict" AND this target has SFTP restrictions (upload or download blocked),
    /// OR when any matching role has file_transfer_only enabled.
    pub shell_blocked: bool,
    /// Per-role flag: when true, blocks shell/exec/forwarding regardless of sftp_permission_mode.
    /// Uses ANY-true semantics across roles (if any matching role has it, it's enforced).
    pub file_transfer_only: bool,
}

impl Default for FileTransferPermission {
    fn default() -> Self {
        Self {
            upload_allowed: false,
            download_allowed: false,
            allowed_paths: None,
            blocked_extensions: None,
            max_file_size: None,
            // Default to blocking shell in strict mode when SFTP is restricted
            shell_blocked: true,
            file_transfer_only: false,
        }
    }
}

#[enum_dispatch]
pub enum ConfigProviderEnum {
    Database(DatabaseConfigProvider),
}

#[enum_dispatch(ConfigProviderEnum)]
#[allow(async_fn_in_trait)]
pub trait ConfigProvider {
    async fn list_users(&mut self) -> Result<Vec<User>, WarpgateError>;

    async fn list_targets(&mut self) -> Result<Vec<Target>, WarpgateError>;

    async fn validate_credential(
        &mut self,
        username: &str,
        client_credential: &AuthCredential,
    ) -> Result<bool, WarpgateError>;

    async fn username_for_sso_credential(
        &mut self,
        client_credential: &AuthCredential,
        preferred_username: Option<String>,
        sso_config: SsoProviderConfig,
    ) -> Result<Option<String>, WarpgateError>;

    async fn apply_sso_role_mappings(
        &mut self,
        username: &str,
        managed_role_names: Option<Vec<String>>,
        active_role_names: Vec<String>,
    ) -> Result<(), WarpgateError>;

    async fn get_credential_policy(
        &mut self,
        username: &str,
        supported_credential_types: &[CredentialKind],
    ) -> Result<Option<Box<dyn CredentialPolicy + Sync + Send>>, WarpgateError>;

    async fn authorize_target(
        &mut self,
        username: &str,
        target: &str,
    ) -> Result<bool, WarpgateError>;

    /// Check if file transfer is allowed for a user to a specific target.
    /// Uses the permissive model: if ANY matching role allows, permission is granted.
    async fn authorize_target_file_transfer(
        &mut self,
        username: &str,
        target: &Target,
    ) -> Result<FileTransferPermission, WarpgateError>;

    async fn update_public_key_last_used(
        &self,
        credential: Option<AuthCredential>,
    ) -> Result<(), WarpgateError>;

    async fn validate_api_token(&mut self, token: &str) -> Result<Option<User>, WarpgateError>;
}

//TODO: move this somewhere
pub async fn authorize_ticket(
    db: &Arc<Mutex<DatabaseConnection>>,
    secret: &Secret<String>,
) -> Result<Option<(e::Ticket::Model, AuthStateUserInfo)>, WarpgateError> {
    let db = db.lock().await;
    let ticket = {
        e::Ticket::Entity::find()
            .filter(e::Ticket::Column::Secret.eq(&secret.expose_secret()[..]))
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

            // TODO maybe Ticket could properly reference the user model and then
            // AuthStateUserInfo could be constructed from it
            let Some(ticket_user) = e::User::Entity::find()
                .filter(e::User::Column::Username.eq(ticket.username.clone()))
                .one(&*db)
                .await?
            else {
                return Err(WarpgateError::UserNotFound(ticket.username.clone()));
            };

            Ok(Some((ticket, (&User::try_from(ticket_user)?).into())))
        }
        None => {
            warn!("Ticket not found: {}", &secret.expose_secret());
            Ok(None)
        }
    }
}

pub async fn consume_ticket(
    db: &Arc<Mutex<DatabaseConnection>>,
    ticket_id: &Uuid,
) -> Result<(), WarpgateError> {
    let db = db.lock().await;
    let ticket = e::Ticket::Entity::find_by_id(*ticket_id).one(&*db).await?;
    let Some(ticket) = ticket else {
        return Err(WarpgateError::InvalidTicket(*ticket_id));
    };

    if let Some(uses_left) = ticket.uses_left {
        let mut model: e::Ticket::ActiveModel = ticket.into();
        model.uses_left = Set(Some(uses_left - 1));
        model.update(&*db).await?;
    }

    Ok(())
}
