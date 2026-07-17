use std::net::IpAddr;
use std::sync::Arc;

use anyhow::bail;
use futures::{SinkExt, StreamExt};
use poem::session::Session;
use poem::web::Data;
use poem::web::websocket::{Message, WebSocket};
use poem::{IntoResponse, Request, handler};
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Enum, Object, OpenApi};
use time::OffsetDateTime;
use tokio::sync::{Mutex, broadcast};
use tracing::{error, warn};
use uuid::Uuid;
use warpgate_admin::api::AnySecurityScheme;
use warpgate_common::auth::{AuthCredential, AuthResult, AuthState, CredentialKind};
use warpgate_common::helpers::username::username_eq_ci;
use warpgate_common::{Secret, WarpgateError};
use warpgate_common_http::auth::{AuthenticatedRequestContext, UnauthenticatedRequestContext};
use warpgate_common_http::logging::get_client_ip;
use warpgate_common_http::{RequestAuthorization, SessionAuthorization};
use warpgate_core::Services;
use warpgate_core::auth::validate_and_add_credential;
use warpgate_core::login_protection::FailedAttemptInfo;
use warpgate_db_entities::Parameters;

use super::common::{emit_unknown_authentication_failed_event, logout};
use crate::common::{
    SessionExt, authorize_session, endpoint_auth, get_auth_state_for_request,
    get_or_create_auth_state_for_request, session_id_for_request,
};
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
    IpBlocked,
    UserLocked,
    IpRejected,
}

#[derive(Object)]
struct LoginFailureResponse {
    state: ApiAuthState,
    /// True when the credential the client just submitted was rejected
    /// (as opposed to merely needing another factor). Lets the UI show an
    /// "incorrect credentials" message and avoid auto-advancing to another
    /// authentication method.
    credential_rejected: bool,
}

impl LoginFailureResponse {
    /// A failure that is not caused by an invalid credential (e.g. blocked IP,
    /// locked user, or simply a credential still being required).
    const fn state(state: ApiAuthState) -> Self {
        Self {
            state,
            credential_rejected: false,
        }
    }

    /// A failure caused by the client submitting an invalid credential.
    const fn credential_rejected(state: ApiAuthState) -> Self {
        Self {
            state,
            credential_rejected: true,
        }
    }
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
    /// When web-approval caching is enabled, the caching window in seconds;
    /// `None` when caching is disabled.
    pub web_approval_caching_grace_seconds: Option<i64>,
}

/// How an web approval should be remembered for bypass
#[derive(Enum, Clone, Copy)]
enum WebApprovalScope {
    Once,
    Target,
    AllTargets,
}

#[derive(Object)]
struct ApproveAuthRequest {
    scope: WebApprovalScope,
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
        ctx: Data<&UnauthenticatedRequestContext>,
        body: Json<LoginRequest>,
    ) -> poem::Result<LoginResponse> {
        let remote_ip = req.remote_addr().as_socket_addr().map(|a| a.ip());
        let services = ctx.services();
        let client_ip: Option<IpAddr> = get_client_ip(req, services)
            .await
            .and_then(|s| s.parse().ok());

        // Check if IP is blocked
        if let Some(ip) = client_ip
            && let Some(block_info) = services.login_protection.check_ip_blocked(&ip).await?
        {
            warn!(
                ip = %ip,
                expires_at = %block_info.expires_at,
                "Login attempt from blocked IP"
            );
            return Ok(LoginResponse::Failure(Json(LoginFailureResponse::state(
                ApiAuthState::IpBlocked,
            ))));
        }

        // Password login can be disabled globally (e.g. SSO-only deployments).
        if ctx.parameters().await?.password_login_mode == Parameters::PasswordLoginMode::Disabled {
            warn!(username = %body.username, "Password login attempt while disabled");
            return Ok(LoginResponse::Failure(Json(LoginFailureResponse::state(
                ApiAuthState::Failed,
            ))));
        }

        // Check if user is locked
        if let Some(_lock_info) = services
            .login_protection
            .check_user_locked(&body.username)
            .await?
        {
            warn!(
                username = %body.username,
                "Login attempt for locked user"
            );
            return Ok(LoginResponse::Failure(Json(LoginFailureResponse::state(
                ApiAuthState::UserLocked,
            ))));
        }

        let state_arc =
            match get_or_create_auth_state_for_request(req, &body.username, &ctx, Some("password"))
                .await
            {
                Err(WarpgateError::UserNotFound(_)) => {
                    let session_id = session_id_for_request(req, &ctx).await?;
                    emit_unknown_authentication_failed_event(
                        session_id,
                        remote_ip,
                        &body.username,
                        "password",
                        "unknown user",
                    );
                    return Ok(LoginResponse::Failure(Json(
                        LoginFailureResponse::credential_rejected(ApiAuthState::Failed),
                    )));
                }
                Err(WarpgateError::IpAddrNotAllowed(..)) => {
                    let session_id = session_id_for_request(req, &ctx).await?;
                    emit_unknown_authentication_failed_event(
                        session_id,
                        remote_ip,
                        &body.username,
                        "password",
                        "IP address not allowed",
                    );
                    return Ok(LoginResponse::Failure(Json(LoginFailureResponse::state(
                        ApiAuthState::IpRejected,
                    ))));
                }
                x => x,
            }?;
        let mut state = state_arc.lock().await;

        let credential_valid = validate_and_add_credential(
            &mut state,
            &AuthCredential::Password(Secret::new(body.password.clone())),
            ctx.services().config_provider.as_ref(),
        )
        .await?;

        match state.verify() {
            AuthResult::Accepted { user_info } => {
                let username = user_info.username.clone();
                authorize_session(req, &ctx, user_info).await?;
                state.emit_authenticated_event_once();
                let state_id = *state.id();
                drop(state);
                ctx.services()
                    .auth_state_store
                    .lock()
                    .await
                    .complete(&state_id)
                    .await;
                // Clear failed attempts on successful login
                if let Some(ip) = client_ip {
                    let _ = services
                        .login_protection
                        .clear_failed_attempts(&ip, &username)
                        .await;
                }
                Ok(LoginResponse::Success)
            }
            x => {
                // Only an invalid password counts as a failed attempt; a valid
                // password that merely needs a second factor is not a failure.
                if !credential_valid {
                    error!("Password authentication failed");
                    if let Some(ip) = client_ip {
                        let _ = services
                            .login_protection
                            .record_failed_attempt(FailedAttemptInfo {
                                username: state.user_info().username.clone(),
                                remote_ip: ip,
                                protocol: "http".to_string(),
                                credential_type: "password".to_string(),
                            })
                            .await;
                    }
                }
                Ok(LoginResponse::Failure(Json(LoginFailureResponse {
                    state: x.into(),
                    credential_rejected: !credential_valid,
                })))
            }
        }
    }

    #[oai(path = "/auth/otp", method = "post", operation_id = "otpLogin")]
    async fn api_auth_otp_login(
        &self,
        req: &Request,
        ctx: Data<&UnauthenticatedRequestContext>,
        body: Json<OtpLoginRequest>,
    ) -> poem::Result<LoginResponse> {
        let services = ctx.services();
        let client_ip: Option<IpAddr> = get_client_ip(req, services)
            .await
            .and_then(|s| s.parse().ok());

        // Check if IP is blocked
        if let Some(ip) = client_ip
            && let Some(block_info) = services.login_protection.check_ip_blocked(&ip).await?
        {
            warn!(
                ip = %ip,
                expires_at = %block_info.expires_at,
                "OTP login attempt from blocked IP"
            );
            return Ok(LoginResponse::Failure(Json(LoginFailureResponse::state(
                ApiAuthState::IpBlocked,
            ))));
        }

        let Some(state_arc) = get_auth_state_for_request(req, &ctx).await? else {
            return Ok(LoginResponse::Failure(Json(LoginFailureResponse::state(
                ApiAuthState::NotStarted,
            ))));
        };

        let mut state = state_arc.lock().await;

        // Check if user is locked
        if let Some(_lock_info) = services
            .login_protection
            .check_user_locked(&state.user_info().username)
            .await?
        {
            warn!(
                username = %state.user_info().username,
                "OTP login attempt for locked user"
            );
            return Ok(LoginResponse::Failure(Json(LoginFailureResponse::state(
                ApiAuthState::UserLocked,
            ))));
        }

        let credential_valid = validate_and_add_credential(
            &mut state,
            &AuthCredential::Otp(body.otp.clone().into()),
            services.config_provider.as_ref(),
        )
        .await?;

        match state.verify() {
            AuthResult::Accepted { user_info } => {
                let username = user_info.username.clone();
                authorize_session(req, &ctx, user_info).await?;
                state.emit_authenticated_event_once();
                let state_id = *state.id();
                drop(state);
                services
                    .auth_state_store
                    .lock()
                    .await
                    .complete(&state_id)
                    .await;
                // Clear failed attempts on successful login
                if let Some(ip) = client_ip {
                    let _ = services
                        .login_protection
                        .clear_failed_attempts(&ip, &username)
                        .await;
                }
                Ok(LoginResponse::Success)
            }
            x => {
                // Only an invalid OTP counts as a failed attempt.
                if !credential_valid && let Some(ip) = client_ip {
                    let _ = services
                        .login_protection
                        .record_failed_attempt(FailedAttemptInfo {
                            username: state.user_info().username.clone(),
                            remote_ip: ip,
                            protocol: "http".to_string(),
                            credential_type: "otp".to_string(),
                        })
                        .await;
                }
                Ok(LoginResponse::Failure(Json(LoginFailureResponse {
                    state: x.into(),
                    credential_rejected: !credential_valid,
                })))
            }
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
        let state_arc = {
            let store = services.auth_state_store.lock().await;
            store.get(&state_id.0)
        };
        let Some(state_arc) = state_arc else {
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
        let state_arc = {
            let store = services.auth_state_store.lock().await;
            store.get(&state_id.0)
        };
        let Some(state_arc) = state_arc else {
            return Ok(AuthStateResponse::NotFound);
        };
        state_arc.lock().await.reject();
        services
            .auth_state_store
            .lock()
            .await
            .complete(&state_id.0)
            .await;
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

        let RequestAuthorization::Session(SessionAuthorization::User { username, .. }) = &ctx.auth
        else {
            return Ok(AuthStateListResponse::NotFound);
        };

        // Snapshot the state handles while briefly holding the store lock, then
        // release it before inspecting/serialising each state. Inspecting a
        // state locks its inner mutex (and `serialize_auth_state_inner` locks
        // the session state store), so doing that work under the auth state
        // store lock would serialise every login against this endpoint.
        let state_arcs = {
            let store = services.auth_state_store.lock().await;
            store.snapshot_states()
        };

        let mut results = vec![];

        for state_arc in state_arcs {
            let is_pending_web_approval = {
                let state = state_arc.lock().await;
                username_eq_ci(&state.user_info().username, username)
                    && matches!(
                        state.verify(),
                        AuthResult::Need(need) if need.contains(&CredentialKind::WebUserApproval)
                    )
            };
            if is_pending_web_approval {
                results.push(serialize_auth_state_inner(state_arc, services).await?);
            }
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
        let state_arc = get_foreign_auth_state(&id, &ctx).await;
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
        body: Json<ApproveAuthRequest>,
        _sec_scheme: AnySecurityScheme,
    ) -> poem::Result<AuthStateResponse> {
        let services = ctx.services();
        let Some(state_arc) = get_foreign_auth_state(&id, &ctx).await else {
            return Ok(AuthStateResponse::NotFound);
        };

        let (auth_result, match_key) = {
            let mut state = state_arc.lock().await;
            state.add_valid_credential(AuthCredential::WebUserApproval);
            (state.verify(), state.web_approval_match_key())
        };

        // Remembered so matching attempts can be bypassed within the grace period.
        if let Some(match_key) = match body.scope {
            WebApprovalScope::Once => None,
            WebApprovalScope::Target => match_key,
            WebApprovalScope::AllTargets => match_key.map(|k| k.for_all_targets()),
        } {
            services
                .auth_state_store
                .lock()
                .await
                .record_web_approval(match_key);
        }

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
        let Some(state_arc) = get_foreign_auth_state(&id, &ctx).await else {
            return Ok(AuthStateResponse::NotFound);
        };
        {
            let mut state = state_arc.lock().await;
            let credential = AuthCredential::WebUserApproval;
            state.emit_authentication_failed_event(Some(&credential), "rejected by user");
            state.reject();
        }
        services.auth_state_store.lock().await.complete(&id).await;
        serialize_auth_state_inner(state_arc, services)
            .await
            .map(Json)
            .map(AuthStateResponse::Ok)
    }
}

/// Used to obtain an AuthState that is not for this request
/// like when doing a web approval of an SSH session
async fn get_foreign_auth_state(
    id: &Uuid,
    ctx: &AuthenticatedRequestContext,
) -> Option<Arc<Mutex<AuthState>>> {
    let RequestAuthorization::Session(SessionAuthorization::User { username, .. }) = &ctx.auth
    else {
        return None;
    };

    let state_arc = {
        let store = ctx.services().auth_state_store.lock().await;
        store.get(id)?
    };

    {
        let state = state_arc.lock().await;
        if !username_eq_ci(&state.user_info().username, username) {
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

    // Clone the session state handle under a brief session-store lock, then
    // release it before locking the per-session mutex, so we never hold the
    // session state store lock across another lock acquisition.
    let session_state = {
        let session_state_store = services.state.lock().await;
        state
            .session_id()
            .and_then(|session_id| session_state_store.sessions.get(session_id).cloned())
    };

    let peer_addr = match session_state {
        Some(x) => x.lock().await.remote_address,
        None => None,
    };

    let web_approval_caching_grace_seconds = services
        .web_approval_grace_period()
        .await?
        .and_then(|d| i64::try_from(d.as_secs()).ok());

    Ok(AuthStateResponseInternal {
        id: state.id().to_string(),
        protocol: state.protocol().to_string(),
        address: peer_addr.map(|x| x.ip().to_string()),
        started: *state.started(),
        state: state.verify().into(),
        identification_string: state.identification_string().to_owned(),
        web_approval_caching_grace_seconds,
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

        loop {
            let id = match rx.recv().await {
                Ok(id) => id,
                // The signal channel only carries wake-ups; if we lag behind we
                // can safely resync on the next event instead of tearing down.
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            };

            // Clone the state handle under a brief store lock, then release it
            // before locking the inner state, so we never hold the store lock
            // across an inner-state lock (which protocol sessions hold across
            // DB I/O) or the socket write.
            let state_arc = {
                let store = auth_state_store.lock().await;
                store.get(&id)
            };
            let belongs_to_user = match state_arc {
                Some(state) => username_eq_ci(&state.lock().await.user_info().username, &username),
                None => false,
            };

            if belongs_to_user {
                sink.send(Message::Text(id.to_string())).await?;
            }
        }

        Ok::<(), anyhow::Error>(())
    }))
}
