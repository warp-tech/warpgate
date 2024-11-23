use std::sync::Arc;

use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, ModelTrait, QueryFilter, Set,
};
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_common::{UserTotpCredential, WarpgateError};
use warpgate_db_entities::OtpCredential;

use super::TokenSecurityScheme;

#[derive(Object)]
struct ExistingOtpCredential {
    id: Uuid,
}

#[derive(Object)]
struct NewOtpCredential {
    secret_key: Vec<u8>,
}

impl From<OtpCredential::Model> for ExistingOtpCredential {
    fn from(credential: OtpCredential::Model) -> Self {
        Self {
            id: credential.id,
        }
    }
}

impl From<&NewOtpCredential> for UserTotpCredential {
    fn from(credential: &NewOtpCredential) -> Self {
        Self {
            key: credential.secret_key.clone().into(),
        }
    }
}

#[derive(ApiResponse)]
enum GetOtpCredentialsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<ExistingOtpCredential>>),
}

#[derive(ApiResponse)]
enum CreateOtpCredentialResponse {
    #[oai(status = 201)]
    Created(Json<ExistingOtpCredential>),
}

pub struct ListApi;

#[OpenApi]
impl ListApi {
    #[oai(
        path = "/users/:user_id/credentials/otp",
        method = "get",
        operation_id = "get_otp_credentials"
    )]
    async fn api_get_all(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        user_id: Path<Uuid>,
        _auth: TokenSecurityScheme,
    ) -> poem::Result<GetOtpCredentialsResponse> {
        let db = db.lock().await;

        let objects = OtpCredential::Entity::find()
            .filter(OtpCredential::Column::UserId.eq(*user_id))
            .all(&*db)
            .await
            .map_err(poem::error::InternalServerError)?;

        Ok(GetOtpCredentialsResponse::Ok(Json(
            objects.into_iter().map(Into::into).collect(),
        )))
    }

    #[oai(
        path = "/users/:user_id/credentials/otp",
        method = "post",
        operation_id = "create_otp_credential"
    )]
    async fn api_create(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        body: Json<NewOtpCredential>,
        user_id: Path<Uuid>,
        _auth: TokenSecurityScheme,
    ) -> poem::Result<CreateOtpCredentialResponse> {
        let db = db.lock().await;

        let object = OtpCredential::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(*user_id),
            ..OtpCredential::ActiveModel::from(UserTotpCredential::from(&*body))
        }
        .insert(&*db)
        .await
        .map_err(WarpgateError::from)?;

        Ok(CreateOtpCredentialResponse::Created(Json(object.into())))
    }
}

#[derive(ApiResponse)]
enum DeleteCredentialResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 404)]
    NotFound,
}

pub struct DetailApi;

#[OpenApi]
impl DetailApi {
    #[oai(
        path = "/users/:user_id/credentials/otp/:id",
        method = "delete",
        operation_id = "delete_otp_credential"
    )]
    async fn api_delete(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        user_id: Path<Uuid>,
        id: Path<Uuid>,
        _auth: TokenSecurityScheme,
    ) -> poem::Result<DeleteCredentialResponse> {
        let db = db.lock().await;

        let Some(role) = OtpCredential::Entity::find_by_id(id.0)
            .filter(OtpCredential::Column::UserId.eq(*user_id))
            .one(&*db)
            .await
            .map_err(poem::error::InternalServerError)?
        else {
            return Ok(DeleteCredentialResponse::NotFound);
        };

        role.delete(&*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        Ok(DeleteCredentialResponse::Deleted)
    }
}
