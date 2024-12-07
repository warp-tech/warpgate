use std::sync::Arc;

use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DbErr, EntityTrait, ModelTrait, QueryFilter,
    Set,
};
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_common::{UserPublicKeyCredential, WarpgateError};
use warpgate_db_entities::PublicKeyCredential;

use super::AnySecurityScheme;

#[derive(Object)]
struct ExistingPublicKeyCredential {
    id: Uuid,
    openssh_public_key: String,
}

#[derive(Object)]
struct NewPublicKeyCredential {
    openssh_public_key: String,
}

impl From<PublicKeyCredential::Model> for ExistingPublicKeyCredential {
    fn from(credential: PublicKeyCredential::Model) -> Self {
        Self {
            id: credential.id,
            openssh_public_key: credential.openssh_public_key,
        }
    }
}

impl From<&NewPublicKeyCredential> for UserPublicKeyCredential {
    fn from(credential: &NewPublicKeyCredential) -> Self {
        Self {
            key: credential.openssh_public_key.clone().into(),
        }
    }
}

#[derive(ApiResponse)]
enum GetPublicKeyCredentialsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<ExistingPublicKeyCredential>>),
}

#[derive(ApiResponse)]
enum CreatePublicKeyCredentialResponse {
    #[oai(status = 201)]
    Created(Json<ExistingPublicKeyCredential>),
}

#[derive(ApiResponse)]
enum UpdatePublicKeyCredentialResponse {
    #[oai(status = 200)]
    Updated(Json<ExistingPublicKeyCredential>),
    #[oai(status = 404)]
    NotFound,
}

pub struct ListApi;

#[OpenApi]
impl ListApi {
    #[oai(
        path = "/users/:user_id/credentials/public-keys",
        method = "get",
        operation_id = "get_public_key_credentials"
    )]
    async fn api_get_all(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        user_id: Path<Uuid>,
        _auth: AnySecurityScheme,
    ) -> Result<GetPublicKeyCredentialsResponse, WarpgateError> {
        let db = db.lock().await;

        let objects = PublicKeyCredential::Entity::find()
            .filter(PublicKeyCredential::Column::UserId.eq(*user_id))
            .all(&*db)
            .await?;

        Ok(GetPublicKeyCredentialsResponse::Ok(Json(
            objects.into_iter().map(Into::into).collect(),
        )))
    }

    #[oai(
        path = "/users/:user_id/credentials/public-keys",
        method = "post",
        operation_id = "create_public_key_credential"
    )]
    async fn api_create(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        body: Json<NewPublicKeyCredential>,
        user_id: Path<Uuid>,
        _auth: AnySecurityScheme,
    ) -> Result<CreatePublicKeyCredentialResponse, WarpgateError> {
        let db = db.lock().await;

        let object = PublicKeyCredential::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(*user_id),
            ..PublicKeyCredential::ActiveModel::from(UserPublicKeyCredential::from(&*body))
        }
        .insert(&*db)
        .await
        .map_err(WarpgateError::from)?;

        Ok(CreatePublicKeyCredentialResponse::Created(Json(
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
        path = "/users/:user_id/credentials/public-keys/:id",
        method = "put",
        operation_id = "update_public_key_credential"
    )]
    async fn api_update(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        body: Json<NewPublicKeyCredential>,
        user_id: Path<Uuid>,
        id: Path<Uuid>,
        _auth: AnySecurityScheme,
    ) -> Result<UpdatePublicKeyCredentialResponse, WarpgateError> {
        let db = db.lock().await;

        let model = PublicKeyCredential::ActiveModel {
            id: Set(id.0),
            user_id: Set(*user_id),
            ..<_>::from(UserPublicKeyCredential::from(&*body))
        }
        .update(&*db)
        .await;

        match model {
            Ok(model) => Ok(UpdatePublicKeyCredentialResponse::Updated(Json(
                model.into(),
            ))),
            Err(DbErr::RecordNotFound(_)) => Ok(UpdatePublicKeyCredentialResponse::NotFound),
            Err(e) => Err(e.into()),
        }
    }

    #[oai(
        path = "/users/:user_id/credentials/public-keys/:id",
        method = "delete",
        operation_id = "delete_public_key_credential"
    )]
    async fn api_delete(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        user_id: Path<Uuid>,
        id: Path<Uuid>,
        _auth: AnySecurityScheme,
    ) -> Result<DeleteCredentialResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(model) = PublicKeyCredential::Entity::find_by_id(id.0)
            .filter(PublicKeyCredential::Column::UserId.eq(*user_id))
            .one(&*db)
            .await?
        else {
            return Ok(DeleteCredentialResponse::NotFound);
        };

        model.delete(&*db).await?;
        Ok(DeleteCredentialResponse::Deleted)
    }
}
