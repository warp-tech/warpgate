use std::collections::HashSet;

mod db;
mod sso_user;

pub use db::DatabaseConfigProvider;
use enum_dispatch::enum_dispatch;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
pub use sso_user::resolve_and_map_sso_user;
use time::OffsetDateTime;
use tracing::warn;
use uuid::Uuid;
use warpgate_common::auth::{AuthCredential, AuthStateUserInfo, CredentialKind, CredentialPolicy};
use warpgate_common::{Secret, Target, User, WarpgateError};
use warpgate_db_entities as e;
use warpgate_sso::SsoProviderConfig;

#[enum_dispatch]
pub enum ConfigProviderEnum {
    Database(DatabaseConfigProvider),
}

#[enum_dispatch(ConfigProviderEnum)]
#[allow(async_fn_in_trait)]
pub trait ConfigProvider {
    async fn list_users(&self) -> Result<Vec<User>, WarpgateError>;

    async fn list_targets(&self) -> Result<Vec<Target>, WarpgateError>;

    async fn get_target_by_name(&self, name: &str) -> Result<Option<Target>, WarpgateError>;

    async fn get_target_by_hostname(&self, hostname: &str)
    -> Result<Option<Target>, WarpgateError>;

    async fn validate_credential(
        &self,
        username: &str,
        client_credential: &AuthCredential,
    ) -> Result<bool, WarpgateError>;

    async fn username_for_sso_credential(
        &self,
        client_credential: &AuthCredential,
        preferred_username: Option<String>,
        sso_config: SsoProviderConfig,
    ) -> Result<Option<String>, WarpgateError>;

    async fn apply_sso_role_mappings(
        &self,
        username: &str,
        managed_role_names: Option<Vec<String>>,
        active_role_names: Vec<String>,
    ) -> Result<(), WarpgateError>;

    /// Similar to `apply_sso_role_mappings` but operates on *admin* roles.
    async fn apply_sso_admin_role_mappings(
        &self,
        username: &str,
        managed_admin_role_names: Option<Vec<String>>,
        active_admin_role_names: Vec<String>,
    ) -> Result<(), WarpgateError>;

    async fn get_credential_policy(
        &self,
        username: &str,
        supported_credential_types: &[CredentialKind],
    ) -> Result<Option<Box<dyn CredentialPolicy + Sync + Send>>, WarpgateError>;

    async fn authorize_target(&self, username: &str, target: &str) -> Result<bool, WarpgateError>;

    async fn authorize_target_by_id(
        &self,
        user_id: Uuid,
        target_id: Uuid,
    ) -> Result<bool, WarpgateError>;

    /// IDs of all targets the user is authorized for, in a single query.
    async fn authorized_target_ids(&self, user_id: Uuid) -> Result<HashSet<Uuid>, WarpgateError>;

    async fn update_public_key_last_used(
        &self,
        credential: Option<AuthCredential>,
    ) -> Result<(), WarpgateError>;

    async fn validate_api_token(&self, token: &str) -> Result<Option<User>, WarpgateError>;
}

//TODO: move this somewhere
pub async fn authorize_ticket(
    db: &DatabaseConnection,
    secret: &Secret<String>,
) -> Result<Option<(e::Ticket::Model, e::Target::Model, AuthStateUserInfo)>, WarpgateError> {
    let ticket = {
        e::Ticket::Entity::find()
            .filter(e::Ticket::Column::Secret.eq(&secret.expose_secret()[..]))
            .one(db)
            .await?
    };
    if let Some(ticket) = ticket {
        if ticket.uses_left == Some(0) {
            warn!("Ticket is used up: {}", &ticket.id);
            return Ok(None);
        }

        if let Some(datetime) = ticket.expiry
            && datetime < OffsetDateTime::now_utc()
        {
            warn!("Ticket has expired: {}", &ticket.id);
            return Ok(None);
        }

        let Some(ticket_user) = e::User::Entity::find_by_id(ticket.user_id).one(db).await? else {
            return Err(WarpgateError::UserNotFound(ticket.user_id.to_string()));
        };

        let Some(ticket_target) = e::Target::Entity::find_by_id(ticket.target_id)
            .one(db)
            .await?
        else {
            warn!("Ticket target not found: {}", &ticket.target_id);
            return Ok(None);
        };

        Ok(Some((
            ticket,
            ticket_target,
            (&User::try_from(ticket_user)?).into(),
        )))
    } else {
        warn!("Ticket not found");
        Ok(None)
    }
}

pub async fn consume_ticket(
    db: &DatabaseConnection,
    ticket_id: &Uuid,
) -> Result<(), WarpgateError> {
    let ticket = e::Ticket::Entity::find_by_id(*ticket_id).one(db).await?;
    let Some(ticket) = ticket else {
        return Err(WarpgateError::InvalidTicket(*ticket_id));
    };

    // Decrement atomically
    if ticket.uses_left.is_some() {
        e::Ticket::Entity::update_many()
            .col_expr(
                e::Ticket::Column::UsesLeft,
                Expr::col(e::Ticket::Column::UsesLeft).sub(1),
            )
            .filter(e::Ticket::Column::Id.eq(*ticket_id))
            .filter(e::Ticket::Column::UsesLeft.gt(0))
            .exec(db)
            .await?;
    }

    Ok(())
}
