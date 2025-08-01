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
use warpgate_common::helpers::locks::DebugLock;
use warpgate_common::{Secret, UserPasswordCredential, WarpgateError};
use warpgate_db_entities::PasswordCredential;

use super::AnySecurityScheme;

#[derive(Object)]
struct ExistingPasswordCredential {
    id: Uuid,
}

#[derive(Object)]
struct NewPasswordCredential {
    password: Secret<String>,
}

impl From<PasswordCredential::Model> for ExistingPasswordCredential {
    fn from(credential: PasswordCredential::Model) -> Self {
        Self { id: credential.id }
    }
}

#[derive(ApiResponse)]
enum GetPasswordCredentialsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<ExistingPasswordCredential>>),
}

#[derive(ApiResponse)]
enum CreatePasswordCredentialResponse {
    #[oai(status = 201)]
    Created(Json<ExistingPasswordCredential>),
}

pub struct ListApi;

#[OpenApi]
impl ListApi {
    #[oai(
        path = "/users/:user_id/credentials/passwords",
        method = "get",
        operation_id = "get_password_credentials"
    )]
    async fn api_get_all(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        user_id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetPasswordCredentialsResponse, WarpgateError> {
        let db = db.lock2().await;

        let objects = PasswordCredential::Entity::find()
            .filter(PasswordCredential::Column::UserId.eq(*user_id))
            .all(&*db)
            .await?;

        Ok(GetPasswordCredentialsResponse::Ok(Json(
            objects.into_iter().map(Into::into).collect(),
        )))
    }

    #[oai(
        path = "/users/:user_id/credentials/passwords",
        method = "post",
        operation_id = "create_password_credential"
    )]
    async fn api_create(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        body: Json<NewPasswordCredential>,
        user_id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<CreatePasswordCredentialResponse, WarpgateError> {
        let db = db.lock2().await;

        let object = PasswordCredential::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(*user_id),
            ..PasswordCredential::ActiveModel::from(UserPasswordCredential::from_password(
                &body.password,
            ))
        }
        .insert(&*db)
        .await
        .map_err(WarpgateError::from)?;

        Ok(CreatePasswordCredentialResponse::Created(Json(
            object.into(),
        )))
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
        path = "/users/:user_id/credentials/passwords/:id",
        method = "delete",
        operation_id = "delete_password_credential"
    )]
    async fn api_delete(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        user_id: Path<Uuid>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<DeleteCredentialResponse, WarpgateError> {
        let db = db.lock2().await;

        let Some(model) = PasswordCredential::Entity::find_by_id(id.0)
            .filter(PasswordCredential::Column::UserId.eq(*user_id))
            .one(&*db)
            .await?
        else {
            return Ok(DeleteCredentialResponse::NotFound);
        };

        model.delete(&*db).await?;
        Ok(DeleteCredentialResponse::Deleted)
    }
}
