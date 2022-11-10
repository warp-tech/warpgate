use std::sync::Arc;

use anyhow::Context;
use http::StatusCode;
use poem::web::Data;
use poem::{FromRequest, Request};
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_common::helpers::hash::generate_ticket_secret;
use warpgate_db_entities::{Token, User};

use crate::common::RequestAuthorization;

pub struct Api;

#[derive(ApiResponse)]
enum GetTokensResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<Token::Model>>),
}

#[derive(Object)]
struct TokenAndSecret {
    token: Token::Model,
    secret: String,
}

#[derive(Object)]
struct CreateTokenRequest {
    name: String,
}

#[derive(ApiResponse)]
enum CreateTokenResponse {
    #[oai(status = 201)]
    Created(Json<TokenAndSecret>),
}

pub(crate) async fn get_user(db: &DatabaseConnection, req: &Request) -> poem::Result<User::Model> {
    let auth: Option<RequestAuthorization> = <_>::from_request_without_body(req).await.ok();
    if let Some(username) = auth.map(|a| a.username().to_owned()) {
        Ok(User::Entity::find()
            .filter(User::Column::Username.eq(username))
            .one(db)
            .await
            .map_err(poem::error::InternalServerError)?
            .ok_or(anyhow::anyhow!("User not found"))?)
    } else {
        Err(poem::error::Error::from_status(StatusCode::UNAUTHORIZED))
    }
}

#[OpenApi]
impl Api {
    #[oai(path = "/tokens", method = "get", operation_id = "get_tokens")]
    async fn api_get_all_tokens(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        req: &Request,
    ) -> poem::Result<GetTokensResponse> {
        use warpgate_db_entities::Token;

        let db = db.lock().await;
        let user = get_user(&*db, req).await?;
        let tokens = Token::Entity::find()
            .filter(Token::Column::UserId.eq(user.id))
            .all(&*db)
            .await
            .map_err(poem::error::InternalServerError)?;

        Ok(GetTokensResponse::Ok(Json(tokens)))
    }

    #[oai(path = "/tokens", method = "post", operation_id = "create_token")]
    async fn api_create_token(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        body: Json<CreateTokenRequest>,
        req: &Request,
    ) -> poem::Result<CreateTokenResponse> {
        use warpgate_db_entities::Token;

        let db = db.lock().await;
        let user = get_user(&*db, req).await?;
        let secret = generate_ticket_secret();
        let values = Token::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(body.name.clone()),
            secret: Set(secret.expose_secret().to_string()),
            created: Set(chrono::Utc::now()),
            user_id: Set(user.id),
            ..Default::default()
        };

        let token = values.insert(&*db).await.context("Error saving token")?;

        Ok(CreateTokenResponse::Created(Json(TokenAndSecret {
            secret: secret.expose_secret().to_string(),
            token,
        })))
    }
}
