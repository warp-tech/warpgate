use crate::common::SessionExt;
use crate::session::SessionMiddleware;
use poem::session::Session;
use poem::web::Data;
use poem::Request;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Enum, Object, OpenApi};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::*;
use warpgate_common::{AuthCredential, AuthResult, Secret, Services};

pub struct Api;

#[derive(Object)]
struct LoginRequest {
    username: String,
    password: String,
    otp: Option<String>,
}

#[derive(Enum)]
enum LoginFailureReason {
    InvalidCredentials,
    OtpNeeded,
}

#[derive(Object)]
struct LoginFailureResponse {
    reason: LoginFailureReason,
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

#[OpenApi]
impl Api {
    #[oai(path = "/auth/login", method = "post", operation_id = "login")]
    async fn api_auth_login(
        &self,
        req: &Request,
        session: &Session,
        services: Data<&Services>,
        session_middleware: Data<&Arc<Mutex<SessionMiddleware>>>,
        body: Json<LoginRequest>,
    ) -> poem::Result<LoginResponse> {
        let mut credentials = vec![AuthCredential::Password(Secret::new(body.password.clone()))];
        if let Some(ref otp) = body.otp {
            credentials.push(AuthCredential::Otp(otp.clone().into()));
        }

        let result = {
            let mut config_provider = services.config_provider.lock().await;
            config_provider
                .authorize(&body.username, &credentials, crate::common::PROTOCOL_NAME)
                .await
                .map_err(|e| e.context("Failed to authorize user"))?
        };

        match result {
            AuthResult::Accepted { username } => {
                let server_handle = session_middleware
                    .lock()
                    .await
                    .create_handle_for(&req)
                    .await?;
                server_handle
                    .lock()
                    .await
                    .set_username(username.clone())
                    .await?;
                info!(%username, "Authenticated");
                session.set_username(username);
                Ok(LoginResponse::Success)
            }
            x => {
                error!("Auth rejected");
                Ok(LoginResponse::Failure(Json(LoginFailureResponse {
                    reason: match x {
                        AuthResult::Accepted { .. } => unreachable!(),
                        AuthResult::Rejected => LoginFailureReason::InvalidCredentials,
                        AuthResult::OtpNeeded => LoginFailureReason::OtpNeeded,
                    },
                })))
            }
        }
    }

    #[oai(path = "/auth/logout", method = "post", operation_id = "logout")]
    async fn api_auth_logout(
        &self,
        session: &Session,
        session_middleware: Data<&Arc<Mutex<SessionMiddleware>>>,
    ) -> poem::Result<LogoutResponse> {
        session_middleware.lock().await.remove_session(session);
        session.clear();
        info!("Logged out");
        Ok(LogoutResponse::Success)
    }
}
