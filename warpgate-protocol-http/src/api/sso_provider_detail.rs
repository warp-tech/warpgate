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
        // Always use the base domain (warp.tavahealth.com) for redirect URI to match OAuth provider registration.
        // This ensures all SSO logins happen through a single registered redirect URI.
        // The session cookie is set for the parent domain (.tavahealth.com) so it will be
        // accessible across all subdomains (warp.tavahealth.com, prometheus.warp.tavahealth.com,
        // reporting.tavahealth.com, etc.) after authentication.
        let mut return_url = config.construct_external_url(
            None,
            provider_config.return_domain_whitelist.as_deref(),
        )?;
        return_url.set_path("@warpgate/api/sso/return");
        let request_host = req.header("host").map(|h| h.to_string());
        info!("SSO redirect URL constructed: {} (scheme={}, host={}, port={:?}, request_host={:?})", 
            &return_url, 
            return_url.scheme(),
            return_url.host_str().unwrap_or("unknown"),
            return_url.port(),
            request_host);

        let client = SsoClient::new(provider_config.provider.clone())?;

        let sso_req = client.start_login(return_url.to_string()).await?;
        let return_host = req
            .header("host")
            .map(|h| h.to_string());        

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
