use std::sync::Arc;

use anyhow::Context;
use poem::web::{Data, RemoteAddr};
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::EntityTrait;
use uuid::Uuid;
use warpgate_common::WarpgateError;
use warpgate_common_http::auth::AuthenticatedRequestContext;
use warpgate_core::ConfigProvider;
use warpgate_db_entities::Target::{self, TargetKind};
use warpgate_web_ssh::WebSshClientManager;

use crate::api::AnySecurityScheme;
use crate::common::endpoint_auth;

pub struct Api;

#[derive(Object)]
struct CreateWebSshSessionBody {
    target_id: Uuid,
}

#[derive(Object)]
struct WebSshSessionCreated {
    session_id: Uuid,
}

#[derive(Object)]
struct WebSshSessionInfo {
    target_name: String,
    target_kind: TargetKind,
}

#[derive(ApiResponse)]
enum CreateWebSshSessionResponse {
    #[oai(status = 201)]
    Created(Json<WebSshSessionCreated>),
    #[oai(status = 403)]
    Forbidden,
    #[oai(status = 404)]
    NotFound,
    #[oai(status = 429)]
    TooManyRequests,
}

#[derive(ApiResponse)]
enum GetWebSshSessionResponse {
    #[oai(status = 200)]
    Ok(Json<WebSshSessionInfo>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteWebSshSessionResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 403)]
    Forbidden,
    #[oai(status = 404)]
    NotFound,
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/web-ssh/sessions",
        method = "post",
        operation_id = "create_web_ssh_session",
        transform = "endpoint_auth"
    )]
    async fn api_create_web_ssh_session(
        &self,
        remote_addr: &RemoteAddr,
        ctx: Data<&AuthenticatedRequestContext>,
        body: Json<CreateWebSshSessionBody>,
        manager: Data<&Arc<WebSshClientManager>>,
        _sec_scheme: AnySecurityScheme,
    ) -> poem::Result<CreateWebSshSessionResponse> {
        let (Some(username), user_id) = (ctx.auth.username(), ctx.auth.user_id()) else {
            return Ok(CreateWebSshSessionResponse::Forbidden);
        };

        let Some(target) = Target::Entity::find_by_id(body.target_id)
            .one(&*ctx.services().db.lock().await)
            .await
            .context("querying target")?
        else {
            return Ok(CreateWebSshSessionResponse::NotFound);
        };

        let services = ctx.services();
        let authorized: bool = services
            .config_provider
            .lock()
            .await
            .authorize_target(username, &target.name)
            .await?;

        if !authorized {
            return Ok(CreateWebSshSessionResponse::Forbidden);
        }

        let session_id = manager
            .create_session(
                services,
                user_id,
                username,
                &target.name,
                remote_addr.0.as_socket_addr().cloned(),
            )
            .await;

        let session_id = match session_id {
            Ok(id) => id,
            Err(WarpgateError::SessionLimitReached) => {
                return Ok(CreateWebSshSessionResponse::TooManyRequests);
            }
            Err(e) => return Err(e.into()),
        };
        Ok(CreateWebSshSessionResponse::Created(Json(
            WebSshSessionCreated { session_id },
        )))
    }

    #[oai(
        path = "/web-ssh/sessions/:session_id",
        method = "get",
        operation_id = "get_web_ssh_session",
        transform = "endpoint_auth"
    )]
    async fn api_get_web_ssh_session(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        session_id: Path<Uuid>,
        manager: Data<&Arc<WebSshClientManager>>,
        _sec_scheme: AnySecurityScheme,
    ) -> poem::Result<GetWebSshSessionResponse> {
        let Some(session) = manager.get_session(*session_id).await else {
            return Ok(GetWebSshSessionResponse::NotFound);
        };

        if session.user_id() != ctx.auth.user_id() {
            return Ok(GetWebSshSessionResponse::NotFound);
        }

        Ok(GetWebSshSessionResponse::Ok(Json(WebSshSessionInfo {
            target_name: session.target_name().into(),
            target_kind: *session.target_kind(),
        })))
    }

    #[oai(
        path = "/web-ssh/sessions/:session_id",
        method = "delete",
        operation_id = "delete_web_ssh_session",
        transform = "endpoint_auth"
    )]
    async fn api_delete_web_ssh_session(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        session_id: Path<Uuid>,
        manager: Data<&Arc<WebSshClientManager>>,
        _sec_scheme: AnySecurityScheme,
    ) -> poem::Result<DeleteWebSshSessionResponse> {
        let Some(session) = manager.get_session(*session_id).await else {
            return Ok(DeleteWebSshSessionResponse::NotFound);
        };

        if session.user_id() != ctx.auth.user_id() {
            return Ok(DeleteWebSshSessionResponse::Forbidden);
        }

        manager.remove_session(*session_id).await;
        Ok(DeleteWebSshSessionResponse::Deleted)
    }
}
