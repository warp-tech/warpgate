use std::sync::Arc;

use chrono::{DateTime, Utc};
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

async fn check_user_ldap_linked(
    db: &DatabaseConnection,
    user_id: Uuid,
) -> Result<bool, WarpgateError> {
    use warpgate_db_entities::User;

    let user = User::Entity::find_by_id(user_id)
        .one(db)
        .await?
        .ok_or_else(|| WarpgateError::UserNotFound(user_id.to_string()))?;

    Ok(user.ldap_server_id.is_some())
}

/// Checks if a user is LDAP-linked and returns an error message if they are.
/// Returns Ok(()) if the user is not LDAP-linked, or a formatted error string if they are.
async fn verify_user_not_ldap_linked(db: &DatabaseConnection, user_id: Uuid) -> Result<(), String> {
    if check_user_ldap_linked(db, user_id).await.unwrap_or(false) {
        Err("Cannot manage SSH keys for LDAP-linked users. Keys are synced from LDAP.".to_string())
    } else {
        Ok(())
    }
}

#[derive(Object)]
struct ExistingPublicKeyCredential {
    id: Uuid,
    label: String,
    date_added: Option<DateTime<Utc>>,
    last_used: Option<DateTime<Utc>>,
    openssh_public_key: String,
}

#[derive(Object)]
struct NewPublicKeyCredential {
    label: String,
    openssh_public_key: String,
}

impl From<PublicKeyCredential::Model> for ExistingPublicKeyCredential {
    fn from(credential: PublicKeyCredential::Model) -> Self {
        Self {
            id: credential.id,
            date_added: credential.date_added,
            last_used: credential.last_used,
            label: credential.label,
            openssh_public_key: credential.openssh_public_key,
        }
    }
}

impl TryFrom<&NewPublicKeyCredential> for UserPublicKeyCredential {
    type Error = WarpgateError;

    fn try_from(credential: &NewPublicKeyCredential) -> Result<Self, WarpgateError> {
        let mut key = russh::keys::PublicKey::from_openssh(&credential.openssh_public_key)
            .map_err(russh::keys::Error::from)?;

        key.set_comment("");

        Ok(Self {
            key: key.to_openssh().map_err(russh::keys::Error::from)?.into(),
        })
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
    #[oai(status = 403)]
    Forbidden(Json<String>),
}

#[derive(ApiResponse)]
enum UpdatePublicKeyCredentialResponse {
    #[oai(status = 200)]
    Updated(Json<ExistingPublicKeyCredential>),
    #[oai(status = 404)]
    NotFound,
    #[oai(status = 403)]
    Forbidden(Json<String>),
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
        _sec_scheme: AnySecurityScheme,
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
        _sec_scheme: AnySecurityScheme,
    ) -> Result<CreatePublicKeyCredentialResponse, WarpgateError> {
        let db = db.lock().await;

        // Check if user is LDAP-linked
        if let Err(msg) = verify_user_not_ldap_linked(&db, *user_id).await {
            return Ok(CreatePublicKeyCredentialResponse::Forbidden(Json(msg)));
        }

        let object = PublicKeyCredential::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(*user_id),
            date_added: Set(Some(Utc::now())),
            last_used: Set(None),
            label: Set(body.label.clone()),
            ..PublicKeyCredential::ActiveModel::from(UserPublicKeyCredential::try_from(&*body)?)
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
    #[oai(status = 403)]
    Forbidden(Json<String>),
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
        _sec_scheme: AnySecurityScheme,
    ) -> Result<UpdatePublicKeyCredentialResponse, WarpgateError> {
        let db = db.lock().await;

        // Check if user is LDAP-linked
        if let Err(msg) = verify_user_not_ldap_linked(&db, *user_id).await {
            return Ok(UpdatePublicKeyCredentialResponse::Forbidden(Json(msg)));
        }

        let model = PublicKeyCredential::ActiveModel {
            id: Set(id.0),
            user_id: Set(*user_id),
            date_added: Set(Some(Utc::now())),
            label: Set(body.label.clone()),
            ..<_>::from(UserPublicKeyCredential::try_from(&*body)?)
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
        _sec_scheme: AnySecurityScheme,
    ) -> Result<DeleteCredentialResponse, WarpgateError> {
        let db = db.lock().await;

        // Check if user is LDAP-linked
        if let Err(msg) = verify_user_not_ldap_linked(&db, *user_id).await {
            return Ok(DeleteCredentialResponse::Forbidden(Json(msg)));
        }

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
