use crate::helpers::ApiResult;
use poem::session::Session;
use poem::web::Data;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use std::sync::Arc;
use tokio::sync::Mutex;
use warpgate_common::{AuthCredential, AuthResult, ConfigProvider, Secret};

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
        config_provider: Data<&Arc<Mutex<dyn ConfigProvider + Send>>>,
        body: Json<LoginRequest>,
    ) -> ApiResult<LoginResponse> {
        let mut config_provider = config_provider.lock().await;
        let result = config_provider
            .authorize(
                &body.username,
                &[AuthCredential::Password(Secret::new(body.password.clone()))],
            )
            .await
            .map_err(|e| e.context("Failed to authorize user"))?;
        match result {
            AuthResult::Accepted { username } => {
                session.set("username", username);
                Ok(LoginResponse::Success)
            }
            AuthResult::Rejected => Ok(LoginResponse::Failure),
        }
    }

    #[oai(path = "/auth/logout", method = "post", operation_id = "logout")]
    async fn api_auth_logout(&self, session: &Session) -> ApiResult<LogoutResponse> {
        session.clear();
        Ok(LogoutResponse::Success)
    }
}
