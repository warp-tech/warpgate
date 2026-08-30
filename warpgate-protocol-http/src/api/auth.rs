use std::sync::Arc;

use anyhow::bail;
use futures::{SinkExt, StreamExt};
use poem::session::Session;
use poem::web::Data;
use poem::web::cookie::CookieJar;
use poem::web::websocket::{Message, WebSocket};
use poem::{FromRequest, IntoResponse, Request, handler};
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::types::ToJSON;
use poem_openapi::{ApiResponse, Enum, Object, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use serde::Serialize;
use time::OffsetDateTime;
use tokio::sync::{Mutex, broadcast};
use tracing::warn;
use uuid::Uuid;
use warpgate_admin::api::cluster_proxy::{
    Owner, ReparseForwardedResponse, forwarded_error, node_owner, parse_forwarded_body,
    proxy_or_serve_pending_login,
};
use warpgate_admin::approvals::{
    ApprovalResolution, Approver, PendingApproval, acting_approver, resolve_pending_approval,
};
use warpgate_common::auth::{ApprovalKind, AuthCredential, AuthResult, AuthState, CredentialKind};
use warpgate_common::helpers::username::username_eq_ci;
use warpgate_common::{Secret, UserSessionId, WarpgateError};
use warpgate_common_http::auth::{AuthenticatedRequestContext, UnauthenticatedRequestContext};
use warpgate_common_http::logging::get_client_ip_addr;
use warpgate_common_http::{RequestAuthorization, SessionAuthorization};
use warpgate_core::Services;
use warpgate_core::approvals::{ApprovalDecision, ApprovalScope};
use warpgate_core::auth::submit_credential;
use warpgate_core::login_protection::FailedAttemptInfo;
use warpgate_db_entities::{Parameters, SessionApprovalRequest, UserSession};

use super::common::{emit_unknown_authentication_failed_event, logout};
use crate::api::auth_scheme::AuthedSession;
use crate::common::{
    SessionExt, authorize_session, get_auth_state_for_request,
    get_or_create_auth_state_for_request, session_id_for_request,
};
use crate::session::SessionStore;
use crate::session_storage::SharedSessionStorage;
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

/// The outcome of acting on an approval request. The decision is applied by the
/// node holding the login, so there is no updated state to hand back here.
#[derive(Object)]
struct ApproveAuthRequest {
    scope: ApprovalScope,
}

#[derive(ApiResponse)]
enum ApprovalActionResponse {
    #[oai(status = 200)]
    Ok,
    #[oai(status = 404)]
    NotFound,
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
        on_login_owner(req, session, &ctx, Some(&body.to_json()), || {
            serve_login(req, &ctx, &body)
        })
        .await
    }

    #[oai(path = "/auth/otp", method = "post", operation_id = "otpLogin")]
    async fn api_auth_otp_login(
        &self,
        req: &Request,
        session: &Session,
        ctx: Data<&UnauthenticatedRequestContext>,
        body: Json<OtpLoginRequest>,
    ) -> poem::Result<LoginResponse> {
        on_login_owner(req, session, &ctx, Some(&body.to_json()), || {
            serve_otp_login(req, &ctx, &body.otp)
        })
        .await
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
        req: &Request,
        session: &Session,
        ctx: Data<&UnauthenticatedRequestContext>,
    ) -> poem::Result<AuthStateResponse> {
        on_login_owner(req, session, &ctx, None::<&()>, || async {
            let services = ctx.services();
            let Some(state_arc) = get_auth_state_for_request(req, &ctx).await? else {
                return Ok(AuthStateResponse::NotFound);
            };
            serialize_auth_state_inner(state_arc, services)
                .await
                .map(Json)
                .map(AuthStateResponse::Ok)
        })
        .await
    }

    #[oai(
        path = "/auth/state",
        method = "delete",
        operation_id = "cancel_default_auth"
    )]
    async fn api_cancel_default_auth(
        &self,
        req: &Request,
        session: &Session,
        ctx: Data<&UnauthenticatedRequestContext>,
    ) -> poem::Result<AuthStateResponse> {
        on_login_owner(req, session, &ctx, None::<&()>, || async {
            let services = ctx.services();
            let Some(state_arc) = get_auth_state_for_request(req, &ctx).await? else {
                return Ok(AuthStateResponse::NotFound);
            };
            // Rejected first, so anything waiting on the state sees the outcome
            // before it is dropped.
            state_arc.lock().await.reject();
            if let Some(session_id) = session.get_session_id() {
                services
                    .auth_state_store
                    .lock()
                    .await
                    .remove_if_same(&session_id, &state_arc);
            }

            serialize_auth_state_inner(state_arc, services)
                .await
                .map(Json)
                .map(AuthStateResponse::Ok)
        })
        .await
    }

    #[oai(
        path = "/auth/web-auth-requests",
        method = "get",
        operation_id = "get_web_auth_requests"
    )]
    async fn get_web_auth_requests(
        &self,
        ctx: AuthedSession,
    ) -> poem::Result<AuthStateListResponse> {
        let services = ctx.services();

        let RequestAuthorization::Session(SessionAuthorization::User { username, .. }) = &ctx.auth
        else {
            return Ok(AuthStateListResponse::NotFound);
        };

        // A login waiting on the user's approval may be held by any node, so the
        // requests are read from the shared request table rather than this
        // node's in-memory store. A row that already carries a decision is
        // awaiting pickup by its owner, so it is no longer something to act on.
        let requests = SessionApprovalRequest::Entity::find()
            .filter(SessionApprovalRequest::Column::Kind.eq(ApprovalKind::User))
            .filter(
                SessionApprovalRequest::Column::Status
                    .eq(SessionApprovalRequest::ApprovalRequestStatus::Pending),
            )
            .order_by_asc(SessionApprovalRequest::Column::Started)
            .all(&services.db)
            .await
            .map_err(WarpgateError::from)?;

        let mut results = vec![];
        for request in requests {
            if username_eq_ci(&request.username, username) {
                results.push(request_to_auth_state(services, request).await?);
            }
        }

        Ok(AuthStateListResponse::Ok(Json(results)))
    }

    #[oai(
        path = "/auth/state/:id",
        method = "get",
        operation_id = "get_auth_state"
    )]
    async fn api_auth_state(
        &self,
        ctx: AuthedSession,
        Path(id): Path<UserSessionId>,
    ) -> poem::Result<AuthStateResponse> {
        // The live state exists only on the node that created it; anywhere else
        // the request row stands in, and it carries everything the approval page
        // shows, which is why this needs no hop to the owner.
        if let Some(state_arc) = local_auth_state_for_user(&ctx, &id).await {
            return serialize_auth_state_inner(state_arc, ctx.services())
                .await
                .map(Json)
                .map(AuthStateResponse::Ok);
        }

        let Some(user) = ctx.auth.as_full_user() else {
            return Ok(AuthStateResponse::NotFound);
        };

        match SessionApprovalRequest::find_user_approval(&ctx.services().db, user.username(), id)
            .await?
        {
            Some(row) => request_to_auth_state(ctx.services(), row)
                .await
                .map(Json)
                .map(AuthStateResponse::Ok),
            None => Ok(AuthStateResponse::NotFound),
        }
    }

    #[oai(
        path = "/auth/state/:id/approve",
        method = "post",
        operation_id = "approve_auth"
    )]
    async fn api_approve_auth(
        &self,
        ctx: AuthedSession,
        id: Path<Uuid>,
        body: Json<ApproveAuthRequest>,
    ) -> poem::Result<ApprovalActionResponse> {
        resolve_own_approval(
            &ctx,
            UserSessionId(*id),
            ApprovalDecision::Approved(body.scope),
        )
        .await
    }

    #[oai(
        path = "/auth/state/:id/reject",
        method = "post",
        operation_id = "reject_auth"
    )]
    async fn api_reject_auth(
        &self,
        ctx: AuthedSession,
        id: Path<Uuid>,
    ) -> poem::Result<ApprovalActionResponse> {
        resolve_own_approval(&ctx, UserSessionId(*id), ApprovalDecision::Rejected).await
    }
}

/// Records the user's decision on their own pending approval.
///
/// The decision is written to the request row and the node holding the login
/// reads it back, so this is served wherever it lands. `find_pending_user_approval`
/// is what enforces that the request belongs to the user asking.
async fn resolve_own_approval(
    ctx: &AuthenticatedRequestContext,
    session_id: UserSessionId,
    decision: ApprovalDecision,
) -> poem::Result<ApprovalActionResponse> {
    // The auth state is what the approval actually satisfies, so the node
    // holding it settles the decision itself. The request row exists to reach
    // the *other* nodes, and it is written from the same signal that tells the
    // user a request is waiting — so acting on that notification immediately
    // can outrun it. Going to the state first makes that race unobservable.
    if local_auth_state_for_user(ctx, &session_id).await.is_some() {
        let actor = acting_approver(ctx);
        return Ok(
            if ctx
                .services()
                .apply_user_approval(session_id, decision, &actor)
                .await?
            {
                ApprovalActionResponse::Ok
            } else {
                ApprovalActionResponse::NotFound
            },
        );
    }

    let Some(user) = ctx.auth.as_full_user() else {
        return Ok(ApprovalActionResponse::NotFound);
    };

    let Some(row) =
        SessionApprovalRequest::find_user_approval(&ctx.services().db, user.username(), session_id)
            .await?
    else {
        return Ok(ApprovalActionResponse::NotFound);
    };
    let Some(pending) = PendingApproval::parse(ctx, row).await? else {
        return Ok(ApprovalActionResponse::NotFound);
    };

    match resolve_pending_approval(ctx, Approver::TheUserThemselves, pending, decision).await? {
        ApprovalResolution::Resolved => Ok(ApprovalActionResponse::Ok),
        ApprovalResolution::NotFound => Ok(ApprovalActionResponse::NotFound),
    }
}

pub(crate) async fn record_failed_login_attempt(
    services: &Services,
    client_ip: Option<std::net::IpAddr>,
    username: &str,
    credential_type: &str,
) {
    let Some(ip) = client_ip else { return };
    let _ = services
        .login_protection
        .record_failed_attempt(FailedAttemptInfo {
            username: username.to_string(),
            remote_ip: ip,
            protocol: crate::common::PROTOCOL_NAME,
            credential_type: credential_type.to_string(),
        })
        .await;
}

/// The password step of a login, on the node that owns the browser session.
async fn serve_login(
    req: &Request,
    ctx: &UnauthenticatedRequestContext,
    body: &LoginRequest,
) -> poem::Result<LoginResponse> {
    let services = ctx.services();
    let client_ip = get_client_ip_addr(req, services).await;

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
        record_failed_login_attempt(services, client_ip, &body.username, "password").await;
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

    let state_arc = match get_or_create_auth_state_for_request(
        req,
        &body.username,
        ctx,
        Some("password"),
    )
    .await
    {
        Err(WarpgateError::UserNotFound(_)) => {
            let session_id = session_id_for_request(req, ctx).await?;
            emit_unknown_authentication_failed_event(
                session_id,
                client_ip,
                &body.username,
                "password",
                "unknown user",
            );
            return Ok(LoginResponse::Failure(Json(
                LoginFailureResponse::credential_rejected(ApiAuthState::Failed),
            )));
        }
        Err(WarpgateError::IpAddrNotAllowed(..)) => {
            let session_id = session_id_for_request(req, ctx).await?;
            emit_unknown_authentication_failed_event(
                session_id,
                client_ip,
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
    submit_and_finalize(
        req,
        ctx,
        &mut state,
        AuthCredential::Password(Secret::new(body.password.clone())),
        "password",
    )
    .await
}

/// The shared tail of every login step: submits the credential and applies the
/// one login-outcome policy — authorize the browser session and clear failed
/// attempts on success; record a failed attempt when the credential itself was
/// rejected (a valid credential that merely needs another factor is not a
/// failure); and mask an overall-`Accepted` state left by an invalid extra
/// credential as a failure to the client.
async fn submit_and_finalize(
    req: &Request,
    ctx: &UnauthenticatedRequestContext,
    state: &mut warpgate_common::auth::AuthState,
    credential: AuthCredential,
    credential_type: &str,
) -> poem::Result<LoginResponse> {
    let services = ctx.services();
    let client_ip = get_client_ip_addr(req, services).await;

    let outcome = submit_credential(
        state,
        credential,
        services.config_provider.as_ref(),
        &services.login_protection,
    )
    .await?;

    match outcome.into_accepted() {
        Ok(user_info) => {
            let username = user_info.username.clone();
            authorize_session(req, ctx, user_info).await?;
            state.emit_authenticated_event_once();
            if let Some(ip) = client_ip {
                let _ = services
                    .login_protection
                    .clear_failed_attempts(&ip, &username)
                    .await;
            }
            Ok(LoginResponse::Success)
        }
        Err(rejection) => {
            if rejection.credential_rejected {
                record_failed_login_attempt(
                    services,
                    client_ip,
                    &state.user_info().username,
                    credential_type,
                )
                .await;
            }
            Ok(LoginResponse::Failure(Json(LoginFailureResponse {
                state: match rejection.state {
                    AuthResult::Accepted { .. } => ApiAuthState::Failed,
                    other => other.into(),
                },
                credential_rejected: rejection.credential_rejected,
            })))
        }
    }
}

/// The OTP step of a login, on the node that owns the browser session.
async fn serve_otp_login(
    req: &Request,
    ctx: &UnauthenticatedRequestContext,
    otp: &str,
) -> poem::Result<LoginResponse> {
    let services = ctx.services();
    let client_ip = get_client_ip_addr(req, services).await;

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

    let Some(state_arc) = get_auth_state_for_request(req, ctx).await? else {
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

    submit_and_finalize(
        req,
        ctx,
        &mut state,
        AuthCredential::Otp(otp.to_owned().into()),
        "otp",
    )
    .await
}

/// The owner of an auth state: auth states are keyed by session id and held
/// only in memory on the node that created them, and the `user_sessions` row
/// records that node (`auth_state_node_id`, stamped at state creation). Rows
/// written before the stamp existed fall back to the session's lifecycle node.
/// An unknown session or a gone owner node both resolve to `Local`, where the
/// store lookup then reports not-found and the caller retries.
async fn auth_state_owner(
    ctx: &UnauthenticatedRequestContext,
    id: Option<UserSessionId>,
) -> poem::Result<Owner> {
    let Some(id) = id else {
        return Ok(Owner::local());
    };
    let Some(session) = UserSession::Entity::find_by_id(id)
        .one(&ctx.services().db)
        .await
        .map_err(poem::error::InternalServerError)?
    else {
        return Ok(Owner::local());
    };
    node_owner(ctx, session.auth_state_node_id.or(session.node_id))
        .await
        .map_err(Into::into)
}

/// Runs a login step (OTP submit, state poll, cancel) for this request's own
/// browser session on the node that owns that session's in-progress login,
/// forwarding the request there when that is another node.
async fn on_login_owner<F, Fut, B: Serialize, R: ReparseForwardedResponse>(
    req: &Request,
    session: &Session,
    ctx: &UnauthenticatedRequestContext,
    body: Option<&B>,
    serve_local: F,
) -> poem::Result<R>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = poem::Result<R>>,
{
    let owner = auth_state_owner(ctx, session.get_session_id()).await?;
    let forwarded = matches!(owner, Owner::Remote(_));
    let authed_before_hop = session.get_auth().is_some();
    let result = proxy_or_serve_pending_login(ctx, req, owner, body, serve_local).await;

    if forwarded {
        // The peer acts on the same browser session - and on success writes the
        // authorization into it - so take its version over the copy this node
        // has been holding since before the hop.
        let jar = <&CookieJar>::from_request_without_body(req).await?;
        let storage = Data::<&SharedSessionStorage>::from_request_without_body(req).await?;
        storage
            .adopt_stored(crate::common::storage_session_id(jar), session)
            .await?;

        if !authed_before_hop && session.get_auth().is_some() {
            // the forwarded request just got us logged in
            // now we must rotate the cookie _here_ since cookies set by a forwarded request are not passed back to the client
            storage
                .rotate_session_id(crate::common::storage_session_id(jar), session)
                .await?;
        }
    }

    result
}

impl ReparseForwardedResponse for LoginResponse {
    async fn reparse_forwarded_response(response: poem::Response) -> poem::Result<Self> {
        match response.status() {
            http::StatusCode::CREATED => Ok(Self::Success),
            http::StatusCode::UNAUTHORIZED => {
                Ok(Self::Failure(Json(parse_forwarded_body(response).await?)))
            }
            _ => Err(forwarded_error(response).await),
        }
    }
}

impl ReparseForwardedResponse for AuthStateResponse {
    async fn reparse_forwarded_response(response: poem::Response) -> poem::Result<Self> {
        match response.status() {
            http::StatusCode::NOT_FOUND => Ok(Self::NotFound),
            http::StatusCode::OK => Ok(Self::Ok(Json(parse_forwarded_body(response).await?))),
            _ => Err(forwarded_error(response).await),
        }
    }
}

/// Renders an approval request row into the approval-page response, purely from
/// row fields, so any node can serve it without holding the login.
async fn request_to_auth_state(
    services: &Services,
    request: SessionApprovalRequest::Model,
) -> poem::Result<AuthStateResponseInternal> {
    let web_approval_caching_grace_seconds = services
        .web_approval_grace_period()
        .await?
        .and_then(|d| i64::try_from(d.as_secs()).ok());
    Ok(AuthStateResponseInternal {
        id: request.session_id.to_string(),
        protocol: request.protocol,
        address: request.remote_address,
        started: request.started,
        state: ApiAuthState::WebUserApprovalNeeded,
        // Only user-approval rows reach here (both lookups filter on the kind),
        // and those always carry the code the user reads back.
        identification_string: request.identification_string.unwrap_or_default(),
        web_approval_caching_grace_seconds,
    })
}

/// Looks up a locally-held auth state, enforcing that it belongs to the
/// requesting user: a user may only act on auth states created for their own
/// username. This runs on the node that holds the state, so a cluster-forwarded
/// request (carrying the origin's user identity) is re-checked here.
async fn local_auth_state_for_user(
    ctx: &AuthenticatedRequestContext,
    id: &UserSessionId,
) -> Option<Arc<Mutex<AuthState>>> {
    // Answering a login's out-of-band request is a user-scoped act, so it takes
    // the same authority as the rest of them — a ticket names a user but does
    // not act as one. This is also the predicate `find_user_approval_row`
    // applies, and the two must agree: which of them serves a request is
    // decided by which node the load balancer picked.
    let username = ctx.auth.as_full_user()?.username().to_owned();
    let state_arc = {
        let store = ctx.services().auth_state_store.lock().await;
        store.get(id)?
    };
    if username_eq_ci(&state_arc.lock().await.user_info().username, &username) {
        Some(state_arc)
    } else {
        None
    }
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
        session_state_store
            .user_sessions
            .get(state.session_id())
            .cloned()
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
        id: state.session_id().to_string(),
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
