//! Bearer tokens for the SCIM provisioning API (`/@warpgate/scim/v2`).
//!
//! A token lets an identity provider create, disable and delete users and
//! manage access-role membership, so creating one requires the permissions
//! that cover everything the token can do, not just configuration access.

use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ActiveModelTrait, EntityTrait, QueryOrder, Set};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::audit::AuditEvent;
use warpgate_common::helpers::hash::{generate_ticket_secret, hash_secret};
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_common_http::errors::invalid_field;
use warpgate_db_entities::ScimToken;

use super::AdminContext;

#[derive(Object)]
struct ScimTokenResponse {
    id: Uuid,
    label: String,
    /// The SSO provider whose credential follows each provisioned user's
    /// primary email, if any.
    sso_provider: Option<String>,
    created: OffsetDateTime,
    expiry: Option<OffsetDateTime>,
    last_used: Option<OffsetDateTime>,
}

impl From<ScimToken::Model> for ScimTokenResponse {
    fn from(token: ScimToken::Model) -> Self {
        Self {
            id: token.id,
            label: token.label,
            sso_provider: token.sso_provider,
            created: token.created,
            expiry: token.expiry,
            last_used: token.last_used,
        }
    }
}

#[derive(Object)]
struct CreateScimTokenRequest {
    label: String,
    sso_provider: Option<String>,
    expiry: Option<OffsetDateTime>,
}

/// The secret is shown exactly once, here.
#[derive(Object)]
struct ScimTokenAndSecret {
    token: ScimTokenResponse,
    secret: String,
}

#[derive(ApiResponse)]
enum GetScimTokensResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<ScimTokenResponse>>),
}

#[derive(ApiResponse)]
enum CreateScimTokenResponse {
    #[oai(status = 201)]
    Created(Json<ScimTokenAndSecret>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
}

#[derive(ApiResponse)]
enum DeleteScimTokenResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 404)]
    NotFound,
}

pub struct ListApi;

#[OpenApi]
impl ListApi {
    #[oai(
        path = "/scim-tokens",
        method = "get",
        operation_id = "get_scim_tokens"
    )]
    async fn api_get_scim_tokens(
        &self,
        admin: AdminContext,
    ) -> Result<GetScimTokensResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;
        let tokens = ScimToken::Entity::find()
            .order_by_asc(ScimToken::Column::Created)
            .all(&admin.services().db)
            .await?;
        Ok(GetScimTokensResponse::Ok(Json(
            tokens.into_iter().map(Into::into).collect(),
        )))
    }

    #[oai(
        path = "/scim-tokens",
        method = "post",
        operation_id = "create_scim_token"
    )]
    async fn api_create_scim_token(
        &self,
        admin: AdminContext,
        body: Json<CreateScimTokenRequest>,
    ) -> Result<CreateScimTokenResponse, WarpgateError> {
        // The token can delete users and access roles, so whoever mints it
        // must be allowed to do that themselves.
        admin.require(AdminPermission::ConfigEdit)?;
        admin.require(AdminPermission::UsersDelete)?;
        admin.require(AdminPermission::AccessRolesDelete)?;

        if body.label.trim().is_empty() {
            return Ok(CreateScimTokenResponse::BadRequest(invalid_field(
                "label",
                "label is empty",
            )));
        }
        if let Some(expiry) = body.expiry
            && expiry <= OffsetDateTime::now_utc()
        {
            return Ok(CreateScimTokenResponse::BadRequest(invalid_field(
                "expiry",
                "expiry is in the past",
            )));
        }
        let sso_provider = body
            .sso_provider
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_owned);
        if let Some(name) = &sso_provider {
            let known = admin
                .services()
                .config
                .lock()
                .await
                .store
                .sso_providers
                .iter()
                .any(|provider| &provider.name == name);
            if !known {
                return Ok(CreateScimTokenResponse::BadRequest(invalid_field(
                    "sso_provider",
                    "no SSO provider with this name is configured",
                )));
            }
        }

        let secret = generate_ticket_secret();
        let token = ScimToken::ActiveModel {
            id: Set(Uuid::new_v4()),
            label: Set(body.label.trim().to_owned()),
            secret_hash: Set(hash_secret(secret.expose_secret())),
            sso_provider: Set(sso_provider),
            created: Set(OffsetDateTime::now_utc()),
            expiry: Set(body.expiry),
            last_used: Set(None),
        }
        .insert(&admin.services().db)
        .await?;

        AuditEvent::ScimTokenCreated {
            token_id: token.id,
            label: token.label.clone(),
            actor_user_id: admin.auth.user_id(),
        }
        .emit();

        Ok(CreateScimTokenResponse::Created(Json(ScimTokenAndSecret {
            token: token.into(),
            secret: secret.expose_secret().clone(),
        })))
    }
}

pub struct DetailApi;

#[OpenApi]
impl DetailApi {
    #[oai(
        path = "/scim-tokens/:id",
        method = "delete",
        operation_id = "delete_scim_token"
    )]
    async fn api_delete_scim_token(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<DeleteScimTokenResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;
        let db = &admin.services().db;
        let Some(token) = ScimToken::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(DeleteScimTokenResponse::NotFound);
        };
        ScimToken::Entity::delete_by_id(token.id).exec(db).await?;
        AuditEvent::ScimTokenDeleted {
            token_id: token.id,
            label: token.label,
            actor_user_id: admin.auth.user_id(),
        }
        .emit();
        Ok(DeleteScimTokenResponse::Deleted)
    }
}
