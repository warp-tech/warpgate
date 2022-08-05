use std::sync::Arc;

use poem::session::Session;
use poem::web::Data;
use poem::Request;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Enum, Object, OpenApi};
use tokio::sync::Mutex;
use tracing::*;
use warpgate_common::auth::{AuthCredential, CredentialKind};
use warpgate_common::{AuthResult, Secret, Services};

use crate::common::{authorize_session, get_auth_state_for_request, SessionExt};
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
    pub state: ApiAuthState,
}

#[derive(ApiResponse)]
enum AuthStateResponse {
    #[oai(status = 200)]
    Ok(Json<AuthStateResponseInternal>),
}

impl From<AuthResult> for ApiAuthState {
    fn from(state: AuthResult) -> Self {
        match state {
            AuthResult::Rejected => ApiAuthState::Failed,
            AuthResult::Need(CredentialKind::Password) => ApiAuthState::PasswordNeeded,
            AuthResult::Need(CredentialKind::Otp) => ApiAuthState::OtpNeeded,
            AuthResult::Need(CredentialKind::Sso) => ApiAuthState::SsoNeeded,
            AuthResult::Need(CredentialKind::PublicKey) => ApiAuthState::Failed,
            AuthResult::NeedMoreCredentials => ApiAuthState::Failed,
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
        let state =
            get_auth_state_for_request(&body.username, session, &mut auth_state_store).await?;

        let mut cp = services.config_provider.lock().await;

        let password_cred = AuthCredential::Password(Secret::new(body.password.clone()));
        if cp
            .validate_credential(&body.username, &password_cred)
            .await?
        {
            state.add_valid_credential(password_cred);
        }

        match state.verify() {
            AuthResult::Accepted { username } => {
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

        let Some(state) = state_id.and_then(|id| auth_state_store.get_mut(&id.0)) else {
            return Ok(LoginResponse::Failure(Json(LoginFailureResponse {
                state: ApiAuthState::NotStarted,
            })))
        };

        let mut cp = services.config_provider.lock().await;

        let otp_cred = AuthCredential::Otp(body.otp.clone().into());
        if cp.validate_credential(state.username(), &otp_cred).await? {
            state.add_valid_credential(otp_cred);
        }

        match state.verify() {
            AuthResult::Accepted { username } => {
                authorize_session(req, username).await?;
                Ok(LoginResponse::Success)
            }
            x => Ok(LoginResponse::Failure(Json(LoginFailureResponse {
                state: x.into(),
            }))),
        }
    }

    #[oai(path = "/auth/state", method = "get", operation_id = "getAuthState")]
    async fn api_auth_state(
        &self,
        session: &Session,
        services: Data<&Services>,
    ) -> poem::Result<AuthStateResponse> {
        let state_id = session.get_auth_state_id();

        let mut auth_state_store = services.auth_state_store.lock().await;

        let Some(state) = state_id.and_then(|id| auth_state_store.get_mut(&id.0)) else {
            return Ok(AuthStateResponse::Ok(Json(AuthStateResponseInternal {
                state: ApiAuthState::NotStarted,
            })));
        };

        Ok(AuthStateResponse::Ok(Json(AuthStateResponseInternal {
            state: state.verify().into(),
        })))
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
}
