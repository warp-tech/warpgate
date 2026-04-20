use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, QueryFilter, Set};
use uuid::Uuid;
use warpgate_common::{AdminPermission, UserTotpCredential, WarpgateError};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::logging::{AuditEvent, CredentialChangedVia};
use warpgate_db_entities::{OtpCredential, User};

use super::AnySecurityScheme;
use crate::api::common::require_admin_permission;

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
        Self { id: credential.id }
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
    #[oai(status = 404)]
    NotFound,
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
        ctx: Data<&AuthenticatedRequestContext>,
        user_id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetOtpCredentialsResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::UsersEdit)).await?;

        let db = ctx.services().db.lock().await;

        let objects = OtpCredential::Entity::find()
            .filter(OtpCredential::Column::UserId.eq(*user_id))
            .all(&*db)
            .await?;

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
        ctx: Data<&AuthenticatedRequestContext>,
        body: Json<NewOtpCredential>,
        user_id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<CreateOtpCredentialResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::UsersEdit)).await?;

        let db = ctx.services().db.lock().await;

        let object = OtpCredential::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(*user_id),
            ..OtpCredential::ActiveModel::from(UserTotpCredential::from(&*body))
        }
        .insert(&*db)
        .await
        .map_err(WarpgateError::from)?;

        let Some(user) = User::Entity::find_by_id(*user_id).one(&*db).await? else {
            return Ok(CreateOtpCredentialResponse::NotFound);
        };

        AuditEvent::CredentialCreated {
            credential_type: "otp".to_string(),
            credential_name: None,
            via: CredentialChangedVia::Admin,
            user_id: *user_id,
            username: user.username,
            actor_user_id: ctx.auth.user_id(),
        }
        .emit();

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
        ctx: Data<&AuthenticatedRequestContext>,
        user_id: Path<Uuid>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<DeleteCredentialResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::UsersEdit)).await?;

        let db = ctx.services().db.lock().await;

        let Some(role) = OtpCredential::Entity::find_by_id(id.0)
            .filter(OtpCredential::Column::UserId.eq(*user_id))
            .one(&*db)
            .await?
        else {
            return Ok(DeleteCredentialResponse::NotFound);
        };

        role.delete(&*db).await?;

        let Some(user) = User::Entity::find_by_id(*user_id).one(&*db).await? else {
            return Ok(DeleteCredentialResponse::NotFound);
        };

        AuditEvent::CredentialDeleted {
            credential_type: "otp".to_string(),
            credential_name: None,
            via: CredentialChangedVia::Admin,
            user_id: *user_id,
            username: user.username,
            actor_user_id: ctx.auth.user_id(),
        }
        .emit();

        Ok(DeleteCredentialResponse::Deleted)
    }
}
