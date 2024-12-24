use poem::session::Session;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use tracing::info;
use warpgate_common::WarpgateError;
use warpgate_db_entities as entities;

use crate::common::RequestAuthorization;
use crate::session::SessionStore;

pub fn logout(session: &Session, session_middleware: &mut SessionStore) {
    session_middleware.remove_session(session);
    session.clear();
    info!("Logged out");
}

pub async fn get_user(
    auth: &RequestAuthorization,
    db: &DatabaseConnection,
) -> Result<Option<entities::User::Model>, WarpgateError> {
    let Some(username) = auth.username() else {
        return Ok(None);
    };

    let Some(user_model) = entities::User::Entity::find()
        .filter(entities::User::Column::Username.eq(username))
        .one(db)
        .await?
    else {
        return Ok(None);
    };

    Ok(Some(user_model))
}
