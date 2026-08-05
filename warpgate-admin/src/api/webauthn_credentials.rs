use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, ModelTrait, QueryFilter};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_core::logging::{AuditEvent, CredentialChangedVia};
use warpgate_db_entities::{User, WebauthnCredential};

use super::AdminContext;

#[derive(Object)]
struct ExistingWebauthnCredential {
    id: Uuid,
    label: String,
    date_added: Option<OffsetDateTime>,
    last_used: Option<OffsetDateTime>,
}

impl From<WebauthnCredential::Model> for ExistingWebauthnCredential {
    fn from(credential: WebauthnCredential::Model) -> Self {
        Self {
            id: credential.id,
            label: credential.label,
            date_added: credential.date_added,
            last_used: credential.last_used,
        }
    }
}

#[derive(ApiResponse)]
enum GetWebauthnCredentialsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<ExistingWebauthnCredential>>),
}

pub struct ListApi;

#[OpenApi]
impl ListApi {
    #[oai(
        path = "/users/:user_id/credentials/webauthn",
        method = "get",
        operation_id = "get_webauthn_credentials"
    )]
    async fn api_get_all(
        &self,
        admin: AdminContext,
        user_id: Path<Uuid>,
    ) -> Result<GetWebauthnCredentialsResponse, WarpgateError> {
        admin.require(AdminPermission::UsersEdit)?;

        let db = &admin.services().db;

        let objects = WebauthnCredential::Entity::find()
            .filter(WebauthnCredential::Column::UserId.eq(*user_id))
            .all(db)
            .await?;

        Ok(GetWebauthnCredentialsResponse::Ok(Json(
            objects.into_iter().map(Into::into).collect(),
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
        path = "/users/:user_id/credentials/webauthn/:id",
        method = "delete",
        operation_id = "delete_webauthn_credential"
    )]
    async fn api_delete(
        &self,
        admin: AdminContext,
        user_id: Path<Uuid>,
        id: Path<Uuid>,
    ) -> Result<DeleteCredentialResponse, WarpgateError> {
        admin.require(AdminPermission::UsersEdit)?;

        let db = &admin.services().db;

        let Some(credential) = WebauthnCredential::Entity::find_by_id(id.0)
            .filter(WebauthnCredential::Column::UserId.eq(*user_id))
            .one(db)
            .await?
        else {
            return Ok(DeleteCredentialResponse::NotFound);
        };

        let label = credential.label.clone();
        credential.delete(db).await?;

        let Some(user) = User::Entity::find_by_id(*user_id).one(db).await? else {
            return Ok(DeleteCredentialResponse::NotFound);
        };

        AuditEvent::CredentialDeleted {
            credential_type: "webauthn".to_string(),
            credential_name: Some(label),
            via: CredentialChangedVia::Admin,
            user_id: *user_id,
            username: user.username,
            actor_user_id: admin.auth.user_id(),
        }
        .emit();

        Ok(DeleteCredentialResponse::Deleted)
    }
}
