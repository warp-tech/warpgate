use poem::session::Session;
use poem::web::Data;
use poem::Request;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use reqwest::Url;
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
        let ext_host = config
            .store
            .external_host
            .as_deref()
            .or_else(|| req.original_uri().host());
        let Some(ext_host) = ext_host  else {
            return Err(poem::Error::from_string("external_host config option is required for SSO", http::status::StatusCode::INTERNAL_SERVER_ERROR));
        };
        let ext_port = config.store.http.listen.port();

        let mut return_url = Url::parse(&format!("https://{ext_host}/@warpgate/api/sso/return"))
            .map_err(|e| {
                poem::Error::from_string(
                    format!("failed to construct the return URL: {e}"),
                    http::status::StatusCode::INTERNAL_SERVER_ERROR,
                )
            })?;

        if ext_port != 443 {
            let _ = return_url.set_port(Some(ext_port));
        }

        let Some(provider_config) = config.store.sso_providers.iter().find(|p| p.name == *name) else {
            return Ok(StartSsoResponse::NotFound);
        };

        let client = SsoClient::new(provider_config.provider.clone());

        let sso_req = client
            .start_login(return_url.to_string())
            .await
            .map_err(poem::error::InternalServerError)?;

        let url = sso_req.auth_url().to_string();
        session.set(SSO_CONTEXT_SESSION_KEY, SsoContext {
            provider: name,
            request: sso_req,
        });

        Ok(StartSsoResponse::Ok(Json(StartSsoResponseParams { url })))
    }
}
