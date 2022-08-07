use poem::session::Session;
use poem::web::Data;
use poem::Request;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use serde::{Deserialize, Serialize};
use warpgate_common::Services;
use warpgate_sso::{SsoClient, SsoLoginRequest};

pub struct Api;

#[derive(Object)]
struct StartSsoResponseParams {
    url: String,
}

#[allow(clippy::large_enum_variant)]
#[derive(ApiResponse)]
enum StartSsoResponse {
    #[oai(status = 200)]
    Ok(Json<StartSsoResponseParams>),
    #[oai(status = 404)]
    NotFound,
}

pub static SSO_CONTEXT_SESSION_KEY: &str = "sso_request";

#[derive(Debug, Serialize, Deserialize)]
pub struct SsoContext {
    pub provider: String,
    pub request: SsoLoginRequest,
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/sso/providers/:name/start",
        method = "get",
        operation_id = "start_sso"
    )]
    async fn api_start_sso(
        &self,
        req: &Request,
        session: &Session,
        services: Data<&Services>,
        name: Path<String>,
    ) -> poem::Result<StartSsoResponse> {
        let config = services.config.lock().await;

        let name = name.0;

        let mut return_url = config.construct_external_url(req.original_uri().host())?;
        return_url.set_path("@warpgate/api/sso/return");

        let Some(provider_config) = config.store.sso_providers.iter().find(|p| p.name == *name) else {
            return Ok(StartSsoResponse::NotFound);
        };

        let client = SsoClient::new(provider_config.provider.clone());

        let sso_req = client
            .start_login(return_url.to_string())
            .await
            .map_err(poem::error::InternalServerError)?;

        let url = sso_req.auth_url().to_string();
        session.set(
            SSO_CONTEXT_SESSION_KEY,
            SsoContext {
                provider: name,
                request: sso_req,
            },
        );

        Ok(StartSsoResponse::Ok(Json(StartSsoResponseParams { url })))
    }
}
