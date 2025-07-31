use chrono::{DateTime, Utc};
use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ActiveModelTrait, ColumnTrait, ModelTrait, QueryFilter, Set};
use uuid::Uuid;
use warpgate_common::helpers::hash::generate_ticket_secret;
use warpgate_common::helpers::locks::DebugLock;
use warpgate_common::WarpgateError;
use warpgate_core::Services;
use warpgate_db_entities::ApiToken;

use super::common::get_user;
use crate::common::{endpoint_auth, RequestAuthorization};

pub struct Api;

#[derive(ApiResponse)]
enum GetApiTokensResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<ExistingApiToken>>),
    #[oai(status = 401)]
    Unauthorized,
}

#[derive(Object)]
struct NewApiToken {
    label: String,
    expiry: DateTime<Utc>,
}

#[derive(Object)]
struct ExistingApiToken {
    id: Uuid,
    label: String,
    created: DateTime<Utc>,
    expiry: DateTime<Utc>,
}

impl From<ApiToken::Model> for ExistingApiToken {
    fn from(token: ApiToken::Model) -> Self {
        Self {
            id: token.id,
            label: token.label,
            created: token.created,
            expiry: token.expiry,
        }
    }
}

#[derive(Object)]
struct TokenAndSecret {
    token: ExistingApiToken,
    secret: String,
}

#[derive(ApiResponse)]
enum CreateApiTokenResponse {
    #[oai(status = 201)]
    Created(Json<TokenAndSecret>),
    #[oai(status = 401)]
    Unauthorized,
}

#[derive(ApiResponse)]
enum DeleteApiTokenResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 401)]
    Unauthorized,
    #[oai(status = 404)]
    NotFound,
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/profile/api-tokens",
        method = "get",
        operation_id = "get_my_api_tokens",
        transform = "endpoint_auth"
    )]
    async fn api_get_api_tokens(
        &self,
        auth: Data<&RequestAuthorization>,
        services: Data<&Services>,
    ) -> Result<GetApiTokensResponse, WarpgateError> {
        let db = services.db.lock2().await;

        let Some(user_model) = get_user(*auth, &db).await? else {
            return Ok(GetApiTokensResponse::Unauthorized);
        };

        let api_tokens = user_model.find_related(ApiToken::Entity).all(&*db).await?;

        Ok(GetApiTokensResponse::Ok(Json(
            api_tokens.into_iter().map(Into::into).collect(),
        )))
    }

    #[oai(
        path = "/profile/api-tokens",
        method = "post",
        operation_id = "create_api_token",
        transform = "endpoint_auth"
    )]
    async fn api_create_api_token(
        &self,
        auth: Data<&RequestAuthorization>,
        services: Data<&Services>,
        body: Json<NewApiToken>,
    ) -> Result<CreateApiTokenResponse, WarpgateError> {
        let db = services.db.lock2().await;

        let Some(user_model) = get_user(&auth, &db).await? else {
            return Ok(CreateApiTokenResponse::Unauthorized);
        };

        let secret = generate_ticket_secret();
        let object = ApiToken::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(user_model.id),
            created: Set(Utc::now()),
            expiry: Set(body.expiry),
            label: Set(body.label.clone()),
            secret: Set(secret.expose_secret().to_string()),
        }
        .insert(&*db)
        .await
        .map_err(WarpgateError::from)?;

        Ok(CreateApiTokenResponse::Created(Json(TokenAndSecret {
            token: object.into(),
            secret: secret.expose_secret().to_string(),
        })))
    }

    #[oai(
        path = "/profile/api-tokens/:id",
        method = "delete",
        operation_id = "delete_my_api_token",
        transform = "endpoint_auth"
    )]
    async fn api_delete_api_token(
        &self,
        auth: Data<&RequestAuthorization>,
        services: Data<&Services>,
        id: Path<Uuid>,
    ) -> Result<DeleteApiTokenResponse, WarpgateError> {
        let db = services.db.lock2().await;

        let Some(user_model) = get_user(&auth, &db).await? else {
            return Ok(DeleteApiTokenResponse::Unauthorized);
        };

        let Some(model) = user_model
            .find_related(ApiToken::Entity)
            .filter(ApiToken::Column::Id.eq(id.0))
            .one(&*db)
            .await?
        else {
            return Ok(DeleteApiTokenResponse::NotFound);
        };

        model.delete(&*db).await?;
        Ok(DeleteApiTokenResponse::Deleted)
    }
}
