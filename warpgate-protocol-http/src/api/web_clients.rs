//! Common API and logic for SSH/RDP web clients

use std::future::Future;
use std::ops::Deref;

use poem::http::StatusCode;
use poem::session::Session;
use poem::{Request, Response};
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object};
use uuid::Uuid;
use warpgate_admin::api::cluster_proxy::{
    ReparseForwardedResponse, forwarded_error, parse_forwarded_body, proxy_or_serve,
};
use warpgate_common::{UserSessionId, WarpgateError};
use warpgate_core::TargetAuthorization;
use warpgate_db_entities::Target::TargetKind;
use warpgate_web_clients_common::{
    ClientManager, ManagedSession, SessionPhase, Sheddable, WebSession,
};

use crate::api::auth_scheme::AuthedSession;
use crate::api::common::{
    WebClientTargetAccess, authorize_web_client_target, web_client_session_owner,
};

#[derive(Object)]
pub struct WebClientSessionCreated {
    pub session_id: UserSessionId,
}

#[derive(Object)]
pub struct WebClientSessionInfo {
    pub target_name: String,
    pub target_kind: TargetKind,
}

#[derive(ApiResponse)]
pub enum CreateWebClientSessionResponse {
    #[oai(status = 201)]
    Created(Json<WebClientSessionCreated>),
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
pub enum GetWebClientSessionResponse {
    #[oai(status = 200)]
    Ok(Json<WebClientSessionInfo>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
pub enum DeleteWebClientSessionResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 404)]
    NotFound,
}

/// `start` registers the session and returns its id
pub async fn create_web_client_session<F, Fut>(
    ctx: &AuthedSession,
    session: &Session,
    target_id: Uuid,
    start: F,
) -> poem::Result<CreateWebClientSessionResponse>
where
    F: FnOnce(TargetAuthorization) -> Fut,
    Fut: Future<Output = Result<UserSessionId, WarpgateError>>,
{
    let authorization = match authorize_web_client_target(ctx, session, target_id).await? {
        WebClientTargetAccess::Authorized(authorization) => authorization,
        WebClientTargetAccess::ReauthRequired => {
            return Ok(CreateWebClientSessionResponse::ReauthRequired);
        }
        WebClientTargetAccess::Forbidden => return Ok(CreateWebClientSessionResponse::Forbidden),
        WebClientTargetAccess::NotFound => return Ok(CreateWebClientSessionResponse::NotFound),
    };

    Ok(match start(authorization).await {
        Ok(session_id) => {
            CreateWebClientSessionResponse::Created(Json(WebClientSessionCreated { session_id }))
        }
        Err(WarpgateError::SessionLimitReached) => CreateWebClientSessionResponse::TooManyRequests,
        Err(WarpgateError::InvalidTarget) => CreateWebClientSessionResponse::NotFound,
        Err(e) => return Err(e.into()),
    })
}

pub async fn get_web_client_session<S, M>(
    ctx: &AuthedSession,
    req: &Request,
    session_id: UserSessionId,
    manager: &ClientManager<S>,
) -> poem::Result<GetWebClientSessionResponse>
where
    S: ManagedSession + Deref<Target = WebSession<M>>,
    M: Sheddable + From<SessionPhase>,
{
    let owner = web_client_session_owner(ctx, session_id).await?;
    proxy_or_serve(ctx, req, owner, None::<&()>, || async {
        match manager
            .lookup_user_session(session_id, ctx.auth.user_id())
            .await
        {
            Some(session) => Ok(GetWebClientSessionResponse::Ok(Json(
                WebClientSessionInfo {
                    target_name: session.target_name().into(),
                    target_kind: *session.target_kind(),
                },
            ))),
            None => Ok(GetWebClientSessionResponse::NotFound),
        }
    })
    .await
}

pub async fn delete_web_client_session<S: ManagedSession>(
    ctx: &AuthedSession,
    req: &Request,
    session_id: UserSessionId,
    manager: &ClientManager<S>,
) -> poem::Result<DeleteWebClientSessionResponse> {
    let owner = web_client_session_owner(ctx, session_id).await?;
    proxy_or_serve(ctx, req, owner, None::<&()>, || async {
        if manager
            .lookup_user_session(session_id, ctx.auth.user_id())
            .await
            .is_none()
        {
            return Ok(DeleteWebClientSessionResponse::NotFound);
        }
        manager.remove_session(session_id).await;
        Ok(DeleteWebClientSessionResponse::Deleted)
    })
    .await
}

impl ReparseForwardedResponse for GetWebClientSessionResponse {
    async fn reparse_forwarded_response(response: Response) -> poem::Result<Self> {
        match response.status() {
            StatusCode::OK => Ok(Self::Ok(Json(parse_forwarded_body(response).await?))),
            StatusCode::NOT_FOUND => Ok(Self::NotFound),
            _ => Err(forwarded_error(response).await),
        }
    }
}

impl ReparseForwardedResponse for DeleteWebClientSessionResponse {
    async fn reparse_forwarded_response(response: Response) -> poem::Result<Self> {
        match response.status() {
            StatusCode::NO_CONTENT => Ok(Self::Deleted),
            StatusCode::NOT_FOUND => Ok(Self::NotFound),
            _ => Err(forwarded_error(response).await),
        }
    }
}
