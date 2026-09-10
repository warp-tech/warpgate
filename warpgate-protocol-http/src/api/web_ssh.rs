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
use warpgate_web_ssh::WebSshClientManager;

use crate::api::auth_scheme::AuthedSession;
use crate::api::common::{
    WebClientTargetAccess, authorize_web_client_target, web_client_session_owner,
};

pub struct Api;

#[derive(Object)]
struct CreateWebSshSessionBody {
    target_id: Uuid,
}

#[derive(Object)]
struct WebSshSessionCreated {
    session_id: UserSessionId,
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
        operation_id = "create_web_ssh_session"
    )]
    async fn api_create_web_ssh_session(
        &self,
        remote_addr: &RemoteAddr,
        session: &Session,
        ctx: AuthedSession,
        body: Json<CreateWebSshSessionBody>,
        manager: Data<&Arc<WebSshClientManager>>,
    ) -> poem::Result<CreateWebSshSessionResponse> {
        let authorization = match authorize_web_client_target(&ctx, session, body.target_id).await?
        {
            WebClientTargetAccess::Authorized(authorization) => authorization,
            WebClientTargetAccess::ReauthRequired => {
                return Ok(CreateWebSshSessionResponse::ReauthRequired);
            }
            WebClientTargetAccess::Forbidden => {
                return Ok(CreateWebSshSessionResponse::Forbidden);
            }
            WebClientTargetAccess::NotFound => return Ok(CreateWebSshSessionResponse::NotFound),
        };

        let session_id = manager
            .create_session(
                ctx.services(),
                authorization,
                remote_addr.0.as_socket_addr().copied(),
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
        operation_id = "get_web_ssh_session"
    )]
    async fn api_get_web_ssh_session(
        &self,
        ctx: AuthedSession,
        req: &Request,
        Path(session_id): Path<UserSessionId>,
        manager: Data<&Arc<WebSshClientManager>>,
    ) -> poem::Result<GetWebSshSessionResponse> {
        let owner = web_client_session_owner(&ctx, session_id).await?;
        proxy_or_serve(&ctx, req, owner, None::<&()>, || async {
            match manager.access(session_id, ctx.auth.user_id()).await {
                SessionAccess::Granted(session) => {
                    Ok(GetWebSshSessionResponse::Ok(Json(WebSshSessionInfo {
                        target_name: session.target_name().into(),
                        target_kind: *session.target_kind(),
                    })))
                }
                SessionAccess::NotFound | SessionAccess::Forbidden => {
                    Ok(GetWebSshSessionResponse::NotFound)
                }
            }
        })
        .await
    }

    #[oai(
        path = "/web-ssh/sessions/:session_id",
        method = "delete",
        operation_id = "delete_web_ssh_session"
    )]
    async fn api_delete_web_ssh_session(
        &self,
        ctx: AuthedSession,
        req: &Request,
        Path(session_id): Path<UserSessionId>,
        manager: Data<&Arc<WebSshClientManager>>,
    ) -> poem::Result<DeleteWebSshSessionResponse> {
        let owner = web_client_session_owner(&ctx, session_id).await?;
        proxy_or_serve(&ctx, req, owner, None::<&()>, || async {
            match manager.access(session_id, ctx.auth.user_id()).await {
                SessionAccess::Granted(_) => {
                    manager.remove_session(session_id).await;
                    Ok(DeleteWebSshSessionResponse::Deleted)
                }
                SessionAccess::Forbidden => Ok(DeleteWebSshSessionResponse::Forbidden),
                SessionAccess::NotFound => Ok(DeleteWebSshSessionResponse::NotFound),
            }
        })
        .await
    }
}

impl ReparseForwardedResponse for GetWebSshSessionResponse {
    async fn reparse_forwarded_response(response: Response) -> poem::Result<Self> {
        match response.status() {
            StatusCode::OK => Ok(Self::Ok(Json(parse_forwarded_body(response).await?))),
            StatusCode::NOT_FOUND => Ok(Self::NotFound),
            _ => Err(forwarded_error(response).await),
        }
    }
}

impl ReparseForwardedResponse for DeleteWebSshSessionResponse {
    async fn reparse_forwarded_response(response: Response) -> poem::Result<Self> {
        match response.status() {
            StatusCode::NO_CONTENT => Ok(Self::Deleted),
            StatusCode::FORBIDDEN => Ok(Self::Forbidden),
            StatusCode::NOT_FOUND => Ok(Self::NotFound),
            _ => Err(forwarded_error(response).await),
        }
    }
}
