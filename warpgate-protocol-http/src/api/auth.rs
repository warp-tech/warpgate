use std::sync::Arc;

use chrono::{DateTime, Utc};
use poem::session::Session;
use poem::web::Data;
use poem::Request;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Enum, Object, OpenApi};
use tokio::sync::Mutex;
use tracing::*;
use uuid::Uuid;
use warpgate_common::auth::{AuthCredential, AuthResult, AuthState, CredentialKind};
use warpgate_common::{Secret, WarpgateError};
use warpgate_core::Services;

use crate::common::{
    authorize_session, endpoint_auth, get_auth_state_for_request, SessionAuthorization, SessionExt,
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
    pub protocol: String,
    pub address: Option<String>,
    pub started: DateTime<Utc>,
    pub state: ApiAuthState,
    pub identification_string: String,
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
            AuthResult::Rejected => ApiAuthState::Failed,
            AuthResult::Need(kinds) => {
                let kind = PREFERRED_NEED_CRED_ORDER
                    .iter()
                    .find(|x| kinds.contains(x))
                    .or(kinds.iter().next());
                match kind {
                    Some(CredentialKind::Password) => ApiAuthState::PasswordNeeded,
                    Some(CredentialKind::Totp) => ApiAuthState::OtpNeeded,
                    Some(CredentialKind::Sso) => ApiAuthState::SsoNeeded,
                    Some(CredentialKind::WebUserApproval) => ApiAuthState::WebUserApprovalNeeded,
                    Some(CredentialKind::PublicKey) => ApiAuthState::PublicKeyNeeded,
                    None => ApiAuthState::Failed,
                }
            }
            AuthResult::Accepted { .. } => ApiAuthState::Success,
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
        services: Data<&Services>,
        body: Json<LoginRequest>,
    ) -> poem::Result<LoginResponse> {
        let mut auth_state_store = services.auth_state_store.lock().await;
        let state_arc = match get_auth_state_for_request(
            &body.username,
            session,
            &mut auth_state_store,
        )
        .await
        {
            Err(WarpgateError::UserNotFound) => {
                return Ok(LoginResponse::Failure(Json(LoginFailureResponse {
                    state: ApiAuthState::Failed,
                })))
            }
            x => x,
        }?;
        let mut state = state_arc.lock().await;

        let mut cp = services.config_provider.lock().await;

        let password_cred = AuthCredential::Password(Secret::new(body.password.clone()));
        if cp
            .validate_credential(state.username(), &password_cred)
            .await?
        {
            state.add_valid_credential(password_cred);
        }

        match state.verify() {
            AuthResult::Accepted { username } => {
                auth_state_store.complete(state.id()).await;
                authorize_session(req, username).await?;
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
        services: Data<&Services>,
        body: Json<OtpLoginRequest>,
    ) -> poem::Result<LoginResponse> {
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
        if cp.validate_credential(state.username(), &otp_cred).await? {
            state.add_valid_credential(otp_cred);
        }

        match state.verify() {
            AuthResult::Accepted { username } => {
                auth_state_store.complete(state.id()).await;
                authorize_session(req, username).await?;
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
        session_middleware.lock().await.remove_session(session);
        session.clear();
        info!("Logged out");
        Ok(LogoutResponse::Success)
    }

    #[oai(
        path = "/auth/state",
        method = "get",
        operation_id = "getDefaultAuthState"
    )]
    async fn api_default_auth_state(
        &self,
        session: &Session,
        services: Data<&Services>,
    ) -> poem::Result<AuthStateResponse> {
        let Some(state_id) = session.get_auth_state_id() else {
            return Ok(AuthStateResponse::NotFound);
        };
        let store = services.auth_state_store.lock().await;
        let Some(state_arc) = store.get(&state_id.0) else {
            return Ok(AuthStateResponse::NotFound);
        };
        serialize_auth_state_inner(state_arc, *services).await
    }

    #[oai(
        path = "/auth/state",
        method = "delete",
        operation_id = "cancelDefaultAuth"
    )]
    async fn api_cancel_default_auth(
        &self,
        session: &Session,
        services: Data<&Services>,
    ) -> poem::Result<AuthStateResponse> {
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
        serialize_auth_state_inner(state_arc, *services).await
    }

    #[oai(
        path = "/auth/state/:id",
        method = "get",
        operation_id = "get_auth_state",
        transform = "endpoint_auth"
    )]
    async fn api_auth_state(
        &self,
        services: Data<&Services>,
        auth: Option<Data<&SessionAuthorization>>,
        id: Path<Uuid>,
    ) -> poem::Result<AuthStateResponse> {
        let state_arc = get_auth_state(&id, &services, auth.map(|x| x.0)).await;
        let Some(state_arc) = state_arc else {
            return Ok(AuthStateResponse::NotFound);
        };
        serialize_auth_state_inner(state_arc, *services).await
    }

    #[oai(
        path = "/auth/state/:id/approve",
        method = "post",
        operation_id = "approve_auth",
        transform = "endpoint_auth"
    )]
    async fn api_approve_auth(
        &self,
        services: Data<&Services>,
        auth: Option<Data<&SessionAuthorization>>,
        id: Path<Uuid>,
    ) -> poem::Result<AuthStateResponse> {
        let Some(state_arc) = get_auth_state(&id, &services, auth.map(|x| x.0)).await else {
            return Ok(AuthStateResponse::NotFound);
        };

        let auth_result = {
            let mut state = state_arc.lock().await;
            state.add_valid_credential(AuthCredential::WebUserApproval);
            state.verify()
        };

        if let AuthResult::Accepted { .. } = auth_result {
            services.auth_state_store.lock().await.complete(&id).await;
        }
        serialize_auth_state_inner(state_arc, *services).await
    }

    #[oai(
        path = "/auth/state/:id/reject",
        method = "post",
        operation_id = "reject_auth",
        transform = "endpoint_auth"
    )]
    async fn api_reject_auth(
        &self,
        services: Data<&Services>,
        auth: Option<Data<&SessionAuthorization>>,
        id: Path<Uuid>,
    ) -> poem::Result<AuthStateResponse> {
        let Some(state_arc) = get_auth_state(&id, &services, auth.map(|x| x.0)).await else {
            return Ok(AuthStateResponse::NotFound);
        };
        state_arc.lock().await.reject();
        services.auth_state_store.lock().await.complete(&id).await;
        serialize_auth_state_inner(state_arc, *services).await
    }
}

async fn get_auth_state(
    id: &Uuid,
    services: &Services,
    auth: Option<&SessionAuthorization>,
) -> Option<Arc<Mutex<AuthState>>> {
    let store = services.auth_state_store.lock().await;

    let Some(auth) = auth else {
        return None;
    };

    let SessionAuthorization::User(username) = auth else {
        return None;
    };

    let Some(state_arc) = store.get(id) else {
        return None;
    };

    {
        let state = state_arc.lock().await;
        if state.username() != username {
            return None;
        }
    }

    Some(state_arc)
}

async fn serialize_auth_state_inner(
    state_arc: Arc<Mutex<AuthState>>,
    services: &Services,
) -> poem::Result<AuthStateResponse> {
    let state = state_arc.lock().await;

    let session_state_store = services.state.lock().await;
    let session_state = state
        .session_id()
        .and_then(|session_id| session_state_store.sessions.get(&session_id));

    let peer_addr = match session_state {
        Some(x) => x.lock().await.remote_address,
        None => None,
    };

    Ok(AuthStateResponse::Ok(Json(AuthStateResponseInternal {
        protocol: state.protocol().to_string(),
        address: peer_addr.map(|x| x.ip().to_string()),
        started: *state.started(),
        state: state.verify().into(),
        identification_string: state.identification_string().to_owned(),
    })))
}
