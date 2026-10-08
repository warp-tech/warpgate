use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ActiveModelTrait, IntoActiveModel, Set};
use warpgate_common::WarpgateError;
use warpgate_db_entities::User;

use super::common::get_user;
use crate::api::auth_scheme::AuthedSession;

pub struct Api;

#[derive(Object)]
struct UserPreferences {
    show_session_menu: bool,
    /// The session menu is turned off globally, so the user's own setting has no effect.
    session_menu_disabled_globally: bool,
}

impl UserPreferences {
    async fn new(ctx: &AuthedSession, user: &User::Model) -> Result<Self, WarpgateError> {
        Ok(Self {
            show_session_menu: user.show_session_menu,
            session_menu_disabled_globally: !ctx.parameters().await?.show_session_menu,
        })
    }
}

#[derive(Object)]
struct UpdateUserPreferences {
    show_session_menu: Option<bool>,
}

#[derive(ApiResponse)]
enum UserPreferencesResponse {
    #[oai(status = 200)]
    Ok(Json<UserPreferences>),
    #[oai(status = 401)]
    Unauthorized,
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/profile/preferences",
        method = "get",
        operation_id = "get_my_preferences"
    )]
    async fn api_get_preferences(
        &self,
        ctx: AuthedSession,
    ) -> Result<UserPreferencesResponse, WarpgateError> {
        let db = &ctx.services().db;

        let Some(full) = ctx.auth.as_full_user() else {
            return Ok(UserPreferencesResponse::Unauthorized);
        };
        let Some(user) = get_user(&full, db).await? else {
            return Ok(UserPreferencesResponse::Unauthorized);
        };

        Ok(UserPreferencesResponse::Ok(Json(
            UserPreferences::new(&ctx, &user).await?,
        )))
    }

    #[oai(
        path = "/profile/preferences",
        method = "put",
        operation_id = "update_my_preferences"
    )]
    async fn api_update_preferences(
        &self,
        ctx: AuthedSession,
        body: Json<UpdateUserPreferences>,
    ) -> Result<UserPreferencesResponse, WarpgateError> {
        let db = &ctx.services().db;

        let Some(full) = ctx.auth.as_full_user() else {
            return Ok(UserPreferencesResponse::Unauthorized);
        };
        let Some(user) = get_user(&full, db).await? else {
            return Ok(UserPreferencesResponse::Unauthorized);
        };

        let mut model = user.into_active_model();
        if let Some(show_session_menu) = body.show_session_menu {
            model.show_session_menu = Set(show_session_menu);
        }
        let user = model.update(db).await?;

        Ok(UserPreferencesResponse::Ok(Json(
            UserPreferences::new(&ctx, &user).await?,
        )))
    }
}
