use std::sync::Arc;

use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DbErr, EntityTrait, IntoActiveModel,
    ModelTrait, QueryFilter, Set,
};
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_common::{UserSsoCredential, WarpgateError};
use warpgate_db_entities::SsoCredential;

#[derive(Object)]
struct ExistingSsoCredential {
    id: Uuid,
    provider: Option<String>,
    email: String,
}

#[derive(Object)]
struct NewSsoCredential {
    provider: Option<String>,
    email: String,
}

impl From<SsoCredential::Model> for ExistingSsoCredential {
    fn from(credential: SsoCredential::Model) -> Self {
        Self {
            id: credential.id,
            email: credential.email,
            provider: credential.provider,
        }
    }
}

impl From<&NewSsoCredential> for UserSsoCredential {
    fn from(credential: &NewSsoCredential) -> Self {
        Self {
            email: credential.email.clone(),
            provider: credential.provider.clone(),
        }
    }
}

#[derive(ApiResponse)]
enum GetSsoCredentialsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<ExistingSsoCredential>>),
}

#[derive(ApiResponse)]
enum CreateSsoCredentialResponse {
    #[oai(status = 201)]
    Created(Json<ExistingSsoCredential>),
}

#[derive(ApiResponse)]
enum UpdateSsoCredentialResponse {
    #[oai(status = 200)]
    Updated(Json<ExistingSsoCredential>),
    #[oai(status = 404)]
    NotFound,
}

pub struct ListApi;

#[OpenApi]
impl ListApi {
    #[oai(
        path = "/users/:user_id/credentials/sso",
        method = "get",
        operation_id = "get_sso_credentials"
    )]
    async fn api_get_all(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        user_id: Path<Uuid>,
    ) -> poem::Result<GetSsoCredentialsResponse> {
        let db = db.lock().await;

        let objects = SsoCredential::Entity::find()
            .filter(SsoCredential::Column::UserId.eq(*user_id))
            .all(&*db)
            .await
            .map_err(poem::error::InternalServerError)?;

        Ok(GetSsoCredentialsResponse::Ok(Json(
            objects.into_iter().map(Into::into).collect(),
        )))
    }

    #[oai(
        path = "/users/:user_id/credentials/sso",
        method = "post",
        operation_id = "create_sso_credential"
    )]
    async fn api_create(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        body: Json<NewSsoCredential>,
        user_id: Path<Uuid>,
    ) -> poem::Result<CreateSsoCredentialResponse> {
        let db = db.lock().await;

        let object = SsoCredential::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(*user_id),
            ..SsoCredential::ActiveModel::from(UserSsoCredential::from(&*body))
        }
        .insert(&*db)
        .await
        .map_err(WarpgateError::from)?;

        Ok(CreateSsoCredentialResponse::Created(Json(object.into())))
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
        path = "/users/:user_id/credentials/sso/:id",
        method = "put",
        operation_id = "update_sso_credential"
    )]
    async fn api_update(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        body: Json<NewSsoCredential>,
        user_id: Path<Uuid>,
        id: Path<Uuid>,
    ) -> poem::Result<UpdateSsoCredentialResponse> {
        let db = db.lock().await;

        let model = SsoCredential::ActiveModel {
            id: Set(id.0),
            user_id: Set(*user_id),
            ..<_>::from(UserSsoCredential::from(&*body))
        }
        .update(&*db)
        .await;

        match model {
            Ok(model) => Ok(UpdateSsoCredentialResponse::Updated(Json(model.into()))),
            Err(DbErr::RecordNotFound(_)) => Ok(UpdateSsoCredentialResponse::NotFound),
            Err(e) => Err(poem::error::InternalServerError(e)),
        }
    }

    #[oai(
        path = "/users/:user_id/credentials/sso/:id",
        method = "delete",
        operation_id = "delete_sso_credential"
    )]
    async fn api_delete(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        user_id: Path<Uuid>,
        id: Path<Uuid>,
    ) -> poem::Result<DeleteCredentialResponse> {
        let db = db.lock().await;

        let Some(role) = SsoCredential::Entity::find_by_id(id.0)
            .filter(SsoCredential::Column::UserId.eq(*user_id))
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
