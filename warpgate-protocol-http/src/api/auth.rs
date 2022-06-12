use crate::common::SessionExt;
use poem::session::Session;
use poem::web::Data;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use warpgate_common::{AuthCredential, AuthResult, Secret, Services};

pub struct Api;

#[derive(Object)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(ApiResponse)]
enum LoginResponse {
    #[oai(status = 201)]
    Success,

    #[oai(status = 401)]
    Failure,
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
        session: &Session,
        services: Data<&Services>,
        body: Json<LoginRequest>,
    ) -> poem::Result<LoginResponse> {
        let mut config_provider = services.config_provider.lock().await;
        let result = config_provider
            .authorize(
                &body.username,
                &[AuthCredential::Password(Secret::new(body.password.clone()))],
            )
            .await
            .map_err(|e| e.context("Failed to authorize user"))?;
        match result {
            AuthResult::Accepted { username } => {
                session.set_username(username);
                Ok(LoginResponse::Success)
            }
            AuthResult::Rejected => Ok(LoginResponse::Failure),
            AuthResult::OTPNeeded => Ok(LoginResponse::Failure), // TODO
        }
    }

    #[oai(path = "/auth/logout", method = "post", operation_id = "logout")]
    async fn api_auth_logout(&self, session: &Session) -> poem::Result<LogoutResponse> {
        session.clear();
        Ok(LogoutResponse::Success)
    }
}
