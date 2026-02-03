use poem::session::Session;
use poem::web::Data;
use poem::Request;
use poem_openapi::param::{Path, Query};
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use serde::{Deserialize, Serialize};
use tracing::*;
use warpgate_common::WarpgateError;
use warpgate_core::Services;
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
    pub next_url: Option<String>,
    pub supports_single_logout: bool,
    pub return_host: Option<String>,
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
        next: Query<Option<String>>,
    ) -> Result<StartSsoResponse, WarpgateError> {
        let config = services.config.lock().await;

        let name = name.0;

        let Some(provider_config) = config.store.sso_providers.iter().find(|p| p.name == *name)
        else {
            return Ok(StartSsoResponse::NotFound);
        };
        let mut return_url = config.construct_external_url(
            Some(req),
            provider_config.return_domain_whitelist.as_deref(),
        )?;
        return_url.set_path("warpgate/api/sso/return");
        debug!("Return URL: {}", &return_url);

        let client = SsoClient::new(provider_config.provider.clone())?;

        let sso_req = client.start_login(return_url.to_string()).await?;
        let return_host = req.header("host").map(|h| h.to_string());

        let url = sso_req.auth_url().to_string();
        session.set(
            SSO_CONTEXT_SESSION_KEY,
            SsoContext {
                provider: name,
                request: sso_req,
                next_url: next.0.clone(),
                supports_single_logout: client.supports_single_logout().await?,
                return_host,
            },
        );

        Ok(StartSsoResponse::Ok(Json(StartSsoResponseParams { url })))
    }
}
