use std::sync::Arc;

use poem::http::StatusCode;
use poem::session::Session;
use poem::web::{Data, RemoteAddr};
use poem::{Request, Response};
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use uuid::Uuid;
use warpgate_admin::api::cluster_proxy::{
    ReparseForwardedResponse, forwarded_error, parse_forwarded_body, proxy_or_serve,
};
use warpgate_common::{UserSessionId, WarpgateError};
use warpgate_db_entities::Target::TargetKind;
use warpgate_web_clients_common::SessionAccess;
use warpgate_web_desktop::WebDesktopClientManager;

use crate::api::auth_scheme::AuthedSession;
use crate::api::common::{
    WebClientTargetAccess, authorize_web_client_target, web_client_session_owner,
};

pub struct Api;

#[derive(Object)]
struct CreateWebDesktopSessionBody {
    target_id: Uuid,
    /// Initial desktop resolution to request from the target, measured by the browser.
    /// Both must be present to take effect; otherwise a default is used.
    width: Option<u16>,
    height: Option<u16>,
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
        operation_id = "create_web_desktop_session"
    )]
    async fn api_create_web_desktop_session(
        &self,
        remote_addr: &RemoteAddr,
        session: &Session,
        ctx: AuthedSession,
        body: Json<CreateWebDesktopSessionBody>,
        manager: Data<&Arc<WebDesktopClientManager>>,
    ) -> poem::Result<CreateWebDesktopSessionResponse> {
        let authorization = match authorize_web_client_target(&ctx, session, body.target_id).await?
        {
            WebClientTargetAccess::Authorized(authorization) => authorization,
            WebClientTargetAccess::ReauthRequired => {
                return Ok(CreateWebDesktopSessionResponse::ReauthRequired);
            }
            WebClientTargetAccess::Forbidden => {
                return Ok(CreateWebDesktopSessionResponse::Forbidden);
            }
            WebClientTargetAccess::NotFound => {
                return Ok(CreateWebDesktopSessionResponse::NotFound);
            }
        };

        let size = body.width.zip(body.height);
        let session_id = manager
            .create_session(
                ctx.services(),
                authorization,
                remote_addr.0.as_socket_addr().copied(),
                size,
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
            WebDesktopSessionCreated {
                session_id: session_id.0,
            },
        )))
    }

    #[oai(
        path = "/web-desktop/sessions/:session_id",
        method = "get",
        operation_id = "get_web_desktop_session"
    )]
    async fn api_get_web_desktop_session(
        &self,
        ctx: AuthedSession,
        req: &Request,
        session_id: Path<Uuid>,
        manager: Data<&Arc<WebDesktopClientManager>>,
    ) -> poem::Result<GetWebDesktopSessionResponse> {
        let owner = web_client_session_owner(&ctx, UserSessionId(*session_id)).await?;
        proxy_or_serve(&ctx, req, owner, None::<&()>, || async {
            match manager
                .access(UserSessionId(*session_id), ctx.auth.user_id())
                .await
            {
                SessionAccess::Granted(session) => Ok(GetWebDesktopSessionResponse::Ok(Json(
                    WebDesktopSessionInfo {
                        target_name: session.target_name().into(),
                        target_kind: *session.target_kind(),
                    },
                ))),
                SessionAccess::NotFound | SessionAccess::Forbidden => {
                    Ok(GetWebDesktopSessionResponse::NotFound)
                }
            }
        })
        .await
    }

    #[oai(
        path = "/web-desktop/sessions/:session_id",
        method = "delete",
        operation_id = "delete_web_desktop_session"
    )]
    async fn api_delete_web_desktop_session(
        &self,
        ctx: AuthedSession,
        req: &Request,
        session_id: Path<Uuid>,
        manager: Data<&Arc<WebDesktopClientManager>>,
    ) -> poem::Result<DeleteWebDesktopSessionResponse> {
        let owner = web_client_session_owner(&ctx, UserSessionId(*session_id)).await?;
        proxy_or_serve(&ctx, req, owner, None::<&()>, || async {
            match manager
                .access(UserSessionId(*session_id), ctx.auth.user_id())
                .await
            {
                SessionAccess::Granted(_) => {
                    manager.remove_session(UserSessionId(*session_id)).await;
                    Ok(DeleteWebDesktopSessionResponse::Deleted)
                }
                SessionAccess::Forbidden => Ok(DeleteWebDesktopSessionResponse::Forbidden),
                SessionAccess::NotFound => Ok(DeleteWebDesktopSessionResponse::NotFound),
            }
        })
        .await
    }
}

impl ReparseForwardedResponse for GetWebDesktopSessionResponse {
    async fn reparse_forwarded_response(response: Response) -> poem::Result<Self> {
        match response.status() {
            StatusCode::OK => Ok(Self::Ok(Json(parse_forwarded_body(response).await?))),
            StatusCode::NOT_FOUND => Ok(Self::NotFound),
            _ => Err(forwarded_error(response).await),
        }
    }
}

impl ReparseForwardedResponse for DeleteWebDesktopSessionResponse {
    async fn reparse_forwarded_response(response: Response) -> poem::Result<Self> {
        match response.status() {
            StatusCode::NO_CONTENT => Ok(Self::Deleted),
            StatusCode::FORBIDDEN => Ok(Self::Forbidden),
            StatusCode::NOT_FOUND => Ok(Self::NotFound),
            _ => Err(forwarded_error(response).await),
        }
    }
}
