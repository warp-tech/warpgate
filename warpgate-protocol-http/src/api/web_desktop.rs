use std::sync::Arc;

use anyhow::Context;
use poem::session::Session;
use poem::web::{Data, RemoteAddr};
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::EntityTrait;
use uuid::Uuid;
use warpgate_common::WarpgateError;
use warpgate_common_http::auth::{AuthenticatedRequestContext, web_reauth_required};
use warpgate_core::ConfigProvider;
use warpgate_db_entities::Target::{self, TargetKind};
use warpgate_web_desktop::WebDesktopClientManager;

use crate::api::AnySecurityScheme;
use crate::common::endpoint_auth;

pub struct Api;

#[derive(Object)]
struct CreateWebDesktopSessionBody {
    target_id: Uuid,
}

#[derive(Object)]
struct WebDesktopSessionCreated {
    session_id: Uuid,
}

#[derive(Object)]
struct WebDesktopSessionInfo {
    target_name: String,
    target_kind: TargetKind,
}

#[derive(ApiResponse)]
enum CreateWebDesktopSessionResponse {
    #[oai(status = 201)]
    Created(Json<WebDesktopSessionCreated>),
    #[oai(status = 401)]
    ReauthRequired,
    #[oai(status = 403)]
    Forbidden,
    #[oai(status = 404)]
    NotFound,
    #[oai(status = 429)]
    TooManyRequests,
}

#[derive(ApiResponse)]
enum GetWebDesktopSessionResponse {
    #[oai(status = 200)]
    Ok(Json<WebDesktopSessionInfo>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteWebDesktopSessionResponse {
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
        path = "/web-desktop/sessions",
        method = "post",
        operation_id = "create_web_desktop_session",
        transform = "endpoint_auth"
    )]
    async fn api_create_web_desktop_session(
        &self,
        remote_addr: &RemoteAddr,
        session: &Session,
        ctx: Data<&AuthenticatedRequestContext>,
        body: Json<CreateWebDesktopSessionBody>,
        manager: Data<&Arc<WebDesktopClientManager>>,
        _sec_scheme: AnySecurityScheme,
    ) -> poem::Result<CreateWebDesktopSessionResponse> {
        let (Some(username), user_id) = (ctx.auth.username(), ctx.auth.user_id()) else {
            return Ok(CreateWebDesktopSessionResponse::Forbidden);
        };

        if web_reauth_required(&ctx, session).await? {
            return Ok(CreateWebDesktopSessionResponse::ReauthRequired);
        }

        // Same global gate as web SSH: the in-browser RDP/VNC desktop clients.
        if !ctx.parameters().await?.web_clients_enabled {
            return Ok(CreateWebDesktopSessionResponse::Forbidden);
        }

        let Some(target) = Target::Entity::find_by_id(body.target_id)
            .one(&ctx.services().db)
            .await
            .context("querying target")?
        else {
            return Ok(CreateWebDesktopSessionResponse::NotFound);
        };

        let services = ctx.services();
        let authorized: bool = services
            .config_provider
            .lock()
            .await
            .authorize_target(username, &target.name)
            .await?;

        if !authorized {
            return Ok(CreateWebDesktopSessionResponse::Forbidden);
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
                return Ok(CreateWebDesktopSessionResponse::TooManyRequests);
            }
            Err(WarpgateError::InvalidTarget) => {
                return Ok(CreateWebDesktopSessionResponse::NotFound);
            }
            Err(e) => return Err(e.into()),
        };
        Ok(CreateWebDesktopSessionResponse::Created(Json(
            WebDesktopSessionCreated { session_id },
        )))
    }

    #[oai(
        path = "/web-desktop/sessions/:session_id",
        method = "get",
        operation_id = "get_web_desktop_session",
        transform = "endpoint_auth"
    )]
    async fn api_get_web_desktop_session(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        session_id: Path<Uuid>,
        manager: Data<&Arc<WebDesktopClientManager>>,
        _sec_scheme: AnySecurityScheme,
    ) -> poem::Result<GetWebDesktopSessionResponse> {
        let Some(session) = manager.get_session(*session_id).await else {
            return Ok(GetWebDesktopSessionResponse::NotFound);
        };

        if session.user_id() != ctx.auth.user_id() {
            return Ok(GetWebDesktopSessionResponse::NotFound);
        }

        Ok(GetWebDesktopSessionResponse::Ok(Json(
            WebDesktopSessionInfo {
                target_name: session.target_name().into(),
                target_kind: *session.target_kind(),
            },
        )))
    }

    #[oai(
        path = "/web-desktop/sessions/:session_id",
        method = "delete",
        operation_id = "delete_web_desktop_session",
        transform = "endpoint_auth"
    )]
    async fn api_delete_web_desktop_session(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        session_id: Path<Uuid>,
        manager: Data<&Arc<WebDesktopClientManager>>,
        _sec_scheme: AnySecurityScheme,
    ) -> poem::Result<DeleteWebDesktopSessionResponse> {
        let Some(session) = manager.get_session(*session_id).await else {
            return Ok(DeleteWebDesktopSessionResponse::NotFound);
        };

        if session.user_id() != ctx.auth.user_id() {
            return Ok(DeleteWebDesktopSessionResponse::Forbidden);
        }

        manager.remove_session(*session_id).await;
        Ok(DeleteWebDesktopSessionResponse::Deleted)
    }
}
