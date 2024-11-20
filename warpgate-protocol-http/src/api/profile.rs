use std::sync::Arc;

use poem::web::Data;
use poem::{FromRequest, Request};
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use tokio::sync::Mutex;
use warpgate_admin::api::users::process_credentials;
use warpgate_common::{User as UserConfig, UserAuthCredential, UserRequireCredentialsPolicy, WarpgateError};
use warpgate_db_entities::User;

use crate::common::{endpoint_auth, SessionAuthorization};

// TODO 2fa status api

#[derive(Object)]
struct ProfileData {
    pub credentials: Vec<UserAuthCredential>,
    pub credential_policy: Option<UserRequireCredentialsPolicy>,
}

pub struct Api;

enum ProfileUserResult {
    Found(User::Model),
    Forbidden,
    NotFound,
}

async fn get_profile_user(
    req: &Request,
    db: &DatabaseConnection,
) -> poem::Result<ProfileUserResult> {
    let auth = Data::<&SessionAuthorization>::from_request_without_body(&req).await?;
    let SessionAuthorization::User(username) = *auth else {
        return Ok(ProfileUserResult::Forbidden);
    };

    let Some(user) = User::Entity::find()
        .filter(User::Column::Username.eq(username))
        .one(&*db)
        .await
        .map_err(poem::error::InternalServerError)?
    else {
        return Ok(ProfileUserResult::NotFound);
    };

    Ok(ProfileUserResult::Found(user))
}

#[derive(ApiResponse)]
enum GetProfileResponse {
    #[oai(status = 200)]
    Ok(Json<ProfileData>),
    #[oai(status = 403)]
    Forbidden,
    #[oai(status = 404)]
    NotFound,
}

#[derive(Object)]
struct ProfileDataRequest {
    credentials: Vec<UserAuthCredential>,
}

#[derive(ApiResponse)]
enum UpdateProfileResponse {
    #[oai(status = 200)]
    Ok(Json<ProfileData>),
    #[oai(status = 403)]
    Forbidden,
    #[oai(status = 404)]
    NotFound,
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/profile",
        method = "get",
        operation_id = "get_profile",
        transform = "endpoint_auth"
    )]
    async fn api_get_profile(
        &self,
        req: &Request,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
    ) -> poem::Result<GetProfileResponse> {
        let db = db.lock().await;
        let user = match get_profile_user(req, &db).await? {
            ProfileUserResult::Found(user) => user,
            ProfileUserResult::Forbidden => return Ok(GetProfileResponse::Forbidden),
            ProfileUserResult::NotFound => return Ok(GetProfileResponse::NotFound),
        };

        let user: UserConfig = user.try_into().map_err(poem::error::InternalServerError)?;

        Ok(GetProfileResponse::Ok(Json(ProfileData {
            credentials: user.credentials,
            credential_policy: user.credential_policy,
        })))
    }

    #[oai(
        path = "/profile",
        method = "put",
        operation_id = "update_profile",
        transform = "endpoint_auth"
    )]
    async fn api_update_profile(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        req: &Request,
        body: Json<ProfileDataRequest>,
    ) -> poem::Result<UpdateProfileResponse> {
        let db = db.lock().await;
        let user = match get_profile_user(req, &db).await? {
            ProfileUserResult::Found(user) => user,
            ProfileUserResult::Forbidden => return Ok(UpdateProfileResponse::Forbidden),
            ProfileUserResult::NotFound => return Ok(UpdateProfileResponse::NotFound),
        };

        let mut model: User::ActiveModel = user.into();
        model.credentials = Set(serde_json::to_value(process_credentials(&body.credentials))
            .map_err(WarpgateError::from)?);

        let user = model
            .update(&*db)
            .await
            .map_err(poem::error::InternalServerError)?;

        let user: UserConfig = user.try_into().map_err(poem::error::InternalServerError)?;

        Ok(UpdateProfileResponse::Ok(Json(ProfileData {
            credentials: user.credentials,
            credential_policy: user.credential_policy,
        })))
    }
}
