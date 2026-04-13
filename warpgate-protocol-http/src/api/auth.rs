use std::sync::Arc;

use anyhow::bail;
use futures::{SinkExt, StreamExt};
use poem::session::Session;
use poem::web::websocket::{Message, WebSocket};
use poem::web::Data;
use poem::{handler, IntoResponse, Request};
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Enum, Object, OpenApi};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::{error, warn};
use uuid::Uuid;
use warpgate_admin::api::AnySecurityScheme;
use warpgate_common::auth::{AuthCredential, AuthResult, AuthState, CredentialKind};
use warpgate_common::{Secret, WarpgateError};
use warpgate_common_http::auth::{AuthenticatedRequestContext, UnauthenticatedRequestContext};
use warpgate_common_http::{RequestAuthorization, SessionAuthorization};
use warpgate_core::{ConfigProvider, Services};

use super::common::logout;
use crate::common::{authorize_session, endpoint_auth, get_auth_state_for_request, SessionExt};
use crate::session::SessionStore;
pub struct Api;

#[derive(Object)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Object)]
struct OtpLoginRequest {
    otp: String,
}

#[derive(Enum)]
enum ApiAuthState {
    NotStarted,
    Failed,
    PasswordNeeded,
    OtpNeeded,
    SsoNeeded,
    WebUserApprovalNeeded,
    PublicKeyNeeded,
    Success,
    IpRejected,
}

#[derive(Object)]
struct LoginFailureResponse {
    state: ApiAuthState,
}

#[derive(ApiResponse)]
enum LoginResponse {
    #[oai(status = 201)]
    Success,

    #[oai(status = 401)]
    Failure(Json<LoginFailureResponse>),
}

#[derive(ApiResponse)]
enum LogoutResponse {
    #[oai(status = 201)]
    Success,
}

#[derive(Object)]
struct AuthStateResponseInternal {
    pub id: String,
    pub protocol: String,
    pub address: Option<String>,
    pub started: OffsetDateTime,
    pub state: ApiAuthState,
    pub identification_string: String,
}

#[derive(ApiResponse)]
enum AuthStateListResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<AuthStateResponseInternal>>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum AuthStateResponse {
    #[oai(status = 200)]
    Ok(Json<AuthStateResponseInternal>),
    #[oai(status = 404)]
    NotFound,
}

const PREFERRED_NEED_CRED_ORDER: &[CredentialKind] = &[
    CredentialKind::PublicKey,
    CredentialKind::Password,
    CredentialKind::Totp,
    CredentialKind::Sso,
    CredentialKind::WebUserApproval,
];

impl From<AuthResult> for ApiAuthState {
    fn from(state: AuthResult) -> Self {
        match state {
            AuthResult::Rejected => Self::Failed,
            AuthResult::Need(kinds) => {
                let kind = PREFERRED_NEED_CRED_ORDER
                    .iter()
                    .find(|x| kinds.contains(x))
                    .or_else(|| kinds.iter().next());
                match kind {
                    Some(CredentialKind::Password) => Self::PasswordNeeded,
                    Some(CredentialKind::Totp) => Self::OtpNeeded,
                    Some(CredentialKind::Sso) => Self::SsoNeeded,
                    Some(CredentialKind::WebUserApproval) => Self::WebUserApprovalNeeded,
                    Some(CredentialKind::PublicKey) => Self::PublicKeyNeeded,
                    Some(CredentialKind::Certificate) => {
                        // Certificate authentication is not supported for HTTP protocol
                        // This credential type is primarily for Kubernetes
                        Self::Failed
                    }
                    None => Self::Failed,
                }
            }
            AuthResult::Accepted { .. } => Self::Success,
        }
    }
}

#[OpenApi]
impl Api {
    #[oai(path = "/auth/login", method = "post", operation_id = "login")]
    async fn api_auth_login(
        &self,
        req: &Request,
        session: &Session,
        ctx: Data<&UnauthenticatedRequestContext>,
        body: Json<LoginRequest>,
    ) -> poem::Result<LoginResponse> {
        let services = ctx.services();
        let remote_ip = req.remote_addr().as_socket_addr().map(|a| a.ip());
        let mut auth_state_store = services.auth_state_store.lock().await;
        let state_arc = match get_auth_state_for_request(
            &body.username,
            session,
            &mut auth_state_store,
            remote_ip,
        )
        .await
        {
            Err(WarpgateError::UserNotFound(_)) => {
                return Ok(LoginResponse::Failure(Json(LoginFailureResponse {
                    state: ApiAuthState::Failed,
                })))
            }
            Err(WarpgateError::IpAddrNotAllowed(..)) => {
                return Ok(LoginResponse::Failure(Json(LoginFailureResponse {
                    state: ApiAuthState::IpRejected,
                })))
            }
            x => x,
        }?;
        let mut state = state_arc.lock().await;

        let mut cp = services.config_provider.lock().await;

        let password_cred = AuthCredential::Password(Secret::new(body.password.clone()));
        if cp
            .validate_credential(&state.user_info().username, &password_cred)
            .await?
        {
            state.add_valid_credential(password_cred);
        }

        match state.verify() {
            AuthResult::Accepted { user_info } => {
                auth_state_store.complete(state.id()).await;
                authorize_session(req, &ctx, user_info).await?;
                Ok(LoginResponse::Success)
            }
            x => {
                error!("Auth rejected");
                Ok(LoginResponse::Failure(Json(LoginFailureResponse {
                    state: x.into(),
                })))
            }
        }
    }

    #[oai(path = "/auth/otp", method = "post", operation_id = "otpLogin")]
    async fn api_auth_otp_login(
        &self,
        req: &Request,
        session: &Session,
        ctx: Data<&UnauthenticatedRequestContext>,
        body: Json<OtpLoginRequest>,
    ) -> poem::Result<LoginResponse> {
        let services = ctx.services();
        let state_id = session.get_auth_state_id();

        let mut auth_state_store = services.auth_state_store.lock().await;

        let Some(state_arc) = state_id.and_then(|id| auth_state_store.get(&id.0)) else {
            return Ok(LoginResponse::Failure(Json(LoginFailureResponse {
                state: ApiAuthState::NotStarted,
            })));
        };

        let mut state = state_arc.lock().await;

        let mut cp = services.config_provider.lock().await;

        let otp_cred = AuthCredential::Otp(body.otp.clone().into());
        if cp
            .validate_credential(&state.user_info().username, &otp_cred)
            .await?
        {
            state.add_valid_credential(otp_cred);
        } else {
            warn!("Invalid OTP for user {}", state.user_info().username);
        }

        match state.verify() {
            AuthResult::Accepted { user_info } => {
                auth_state_store.complete(state.id()).await;
                authorize_session(req, &ctx, user_info).await?;
                Ok(LoginResponse::Success)
            }
            x => Ok(LoginResponse::Failure(Json(LoginFailureResponse {
                state: x.into(),
            }))),
        }
    }

    #[oai(path = "/auth/logout", method = "post", operation_id = "logout")]
    async fn api_auth_logout(
        &self,
        session: &Session,
        session_middleware: Data<&Arc<Mutex<SessionStore>>>,
    ) -> poem::Result<LogoutResponse> {
        logout(session, &mut *session_middleware.lock().await);
        Ok(LogoutResponse::Success)
    }

    #[oai(
        path = "/auth/state",
        method = "get",
        operation_id = "get_default_auth_state"
    )]
    async fn api_default_auth_state(
        &self,
        session: &Session,
        ctx: Data<&UnauthenticatedRequestContext>,
    ) -> poem::Result<AuthStateResponse> {
        let services = ctx.services();
        let Some(state_id) = session.get_auth_state_id() else {
            return Ok(AuthStateResponse::NotFound);
        };
        let store = services.auth_state_store.lock().await;
        let Some(state_arc) = store.get(&state_id.0) else {
            return Ok(AuthStateResponse::NotFound);
        };
        serialize_auth_state_inner(state_arc, services)
            .await
            .map(Json)
            .map(AuthStateResponse::Ok)
    }

    #[oai(
        path = "/auth/state",
        method = "delete",
        operation_id = "cancel_default_auth"
    )]
    async fn api_cancel_default_auth(
        &self,
        session: &Session,
        ctx: Data<&UnauthenticatedRequestContext>,
    ) -> poem::Result<AuthStateResponse> {
        let services = ctx.services();
        let Some(state_id) = session.get_auth_state_id() else {
            return Ok(AuthStateResponse::NotFound);
        };
        let mut store = services.auth_state_store.lock().await;
        let Some(state_arc) = store.get(&state_id.0) else {
            return Ok(AuthStateResponse::NotFound);
        };
        state_arc.lock().await.reject();
        store.complete(&state_id.0).await;
        session.clear_auth_state();

        serialize_auth_state_inner(state_arc, services)
            .await
            .map(Json)
            .map(AuthStateResponse::Ok)
    }

    #[oai(
        path = "/auth/web-auth-requests",
        method = "get",
        operation_id = "get_web_auth_requests",
        transform = "endpoint_auth"
    )]
    async fn get_web_auth_requests(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        _sec_scheme: AnySecurityScheme,
    ) -> poem::Result<AuthStateListResponse> {
        let services = ctx.services();
        let store = services.auth_state_store.lock().await;

        let RequestAuthorization::Session(SessionAuthorization::User { username, .. }) = &ctx.auth
        else {
            return Ok(AuthStateListResponse::NotFound);
        };

        let state_arcs = store.all_pending_web_auths_for_user(username).await;

        let mut results = vec![];

        for state_arc in state_arcs {
            results.push(serialize_auth_state_inner(state_arc, services).await?);
        }

        Ok(AuthStateListResponse::Ok(Json(results)))
    }

    #[oai(
        path = "/auth/state/:id",
        method = "get",
        operation_id = "get_auth_state",
        transform = "endpoint_auth"
    )]
    async fn api_auth_state(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
    ) -> poem::Result<AuthStateResponse> {
        let services = ctx.services();
        let state_arc = get_auth_state(&id, &ctx).await;
        let Some(state_arc) = state_arc else {
            return Ok(AuthStateResponse::NotFound);
        };
        serialize_auth_state_inner(state_arc, services)
            .await
            .map(Json)
            .map(AuthStateResponse::Ok)
    }

    #[oai(
        path = "/auth/state/:id/approve",
        method = "post",
        operation_id = "approve_auth",
        transform = "endpoint_auth"
    )]
    async fn api_approve_auth(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> poem::Result<AuthStateResponse> {
        let services = ctx.services();
        let Some(state_arc) = get_auth_state(&id, &ctx).await else {
            return Ok(AuthStateResponse::NotFound);
        };

        let auth_result = {
            let mut state = state_arc.lock().await;
            state.add_valid_credential(AuthCredential::WebUserApproval);
            state.verify()
        };

        if let AuthResult::Accepted { .. } = auth_result {
            let mut store = services.auth_state_store.lock().await;
            store.complete(&id).await;
        }
        serialize_auth_state_inner(state_arc, services)
            .await
            .map(Json)
            .map(AuthStateResponse::Ok)
    }

    #[oai(
        path = "/auth/state/:id/reject",
        method = "post",
        operation_id = "reject_auth",
        transform = "endpoint_auth"
    )]
    async fn api_reject_auth(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> poem::Result<AuthStateResponse> {
        let services = ctx.services();
        let Some(state_arc) = get_auth_state(&id, &ctx).await else {
            return Ok(AuthStateResponse::NotFound);
        };
        state_arc.lock().await.reject();
        services.auth_state_store.lock().await.complete(&id).await;
        serialize_auth_state_inner(state_arc, services)
            .await
            .map(Json)
            .map(AuthStateResponse::Ok)
    }
}

async fn get_auth_state(
    id: &Uuid,
    ctx: &AuthenticatedRequestContext,
) -> Option<Arc<Mutex<AuthState>>> {
    let store = ctx.services().auth_state_store.lock().await;

    let RequestAuthorization::Session(SessionAuthorization::User { username, .. }) = &ctx.auth
    else {
        return None;
    };

    let state_arc = store.get(id)?;

    {
        let state = state_arc.lock().await;
        if &state.user_info().username != username {
            return None;
        }
    }

    Some(state_arc)
}

async fn serialize_auth_state_inner(
    state_arc: Arc<Mutex<AuthState>>,
    services: &Services,
) -> poem::Result<AuthStateResponseInternal> {
    let state = state_arc.lock().await;

    let session_state_store = services.state.lock().await;
    let session_state = state
        .session_id()
        .and_then(|session_id| session_state_store.sessions.get(session_id));

    let peer_addr = match session_state {
        Some(x) => x.lock().await.remote_address,
        None => None,
    };

    Ok(AuthStateResponseInternal {
        id: state.id().to_string(),
        protocol: state.protocol().to_string(),
        address: peer_addr.map(|x| x.ip().to_string()),
        started: *state.started(),
        state: state.verify().into(),
        identification_string: state.identification_string().to_owned(),
    })
}

#[handler]
pub async fn api_get_web_auth_requests_stream(
    ws: WebSocket,
    ctx: Data<&AuthenticatedRequestContext>,
) -> anyhow::Result<impl IntoResponse> {
    let services = ctx.services();
    let auth_state_store = services.auth_state_store.clone();

    let username = match &ctx.auth {
        RequestAuthorization::Session(SessionAuthorization::User { username, .. }) => {
            username.clone()
        }
        _ => bail!("Only session-based user auth is supported for this endpoint"),
    };

    let mut rx = {
        let mut s = auth_state_store.lock().await;
        s.subscribe_web_auth_request()
    };

    Ok(ws.on_upgrade(|socket| async move {
        let (mut sink, _) = socket.split();

        while let Ok(id) = rx.recv().await {
            let auth_state_store = auth_state_store.lock().await;
            if let Some(state) = auth_state_store.get(&id) {
                let state = state.lock().await;
                if state.user_info().username == username {
                    sink.send(Message::Text(id.to_string())).await?;
                }
            }
        }

        Ok::<(), anyhow::Error>(())
    }))
}
