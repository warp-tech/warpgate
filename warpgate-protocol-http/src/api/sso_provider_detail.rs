use poem::Request;
use poem::session::Session;
use poem::web::Data;
use poem_openapi::param::{Path, Query};
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use serde::{Deserialize, Serialize};
use tracing::debug;
use warpgate_common::WarpgateError;
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::ext::construct_external_url;
use warpgate_sso::{SsoClient, SsoLoginRequest, SsoReturnUrlDomainPreference};

use crate::common::{host_is_subdomain_of_or_equal, is_localhost_host};

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
    /// The request originates from a domain that has no cookie domain relationship
    /// with `external_host` while `return_url_domain` is `external_host`
    #[oai(status = 400)]
    IncompatibleSsoDomain,
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
        ctx: Data<&UnauthenticatedRequestContext>,
        name: Path<String>,
        next: Query<Option<String>>,
    ) -> Result<StartSsoResponse, WarpgateError> {
        let config = ctx.services().config.lock().await;

        let name = name.0;

        let Some(provider_config) = config.store.sso_providers.iter().find(|p| p.name == *name)
        else {
            return Ok(StartSsoResponse::NotFound);
        };

        if matches!(
            provider_config.return_url_domain,
            SsoReturnUrlDomainPreference::ExternalHost
        ) && let (Some(request_host), Some(external_host)) = (
            ctx.trusted_hostname(req),
            config.store.external_host.as_deref(),
        ) {
            if !is_localhost_host(&request_host)
                && !host_is_subdomain_of_or_equal(&request_host, external_host)
            {
                return Ok(StartSsoResponse::IncompatibleSsoDomain);
            }
        }

        let mut return_url = construct_external_url(
            match provider_config.return_url_domain {
                // Let `construct_external_url` fall back to config file
                SsoReturnUrlDomainPreference::ExternalHost => None,
                SsoReturnUrlDomainPreference::HostHeader => Some(req),
            },
            &config,
            provider_config.return_domain_whitelist.as_deref(),
        )
        .await?;
        return_url.set_path(&format!(
            "{}warpgate/api/sso/return",
            provider_config.return_url_prefix
        ));
        debug!("Return URL: {return_url}");

        let client = SsoClient::new(provider_config.provider.clone())?;

        let sso_req = client.start_login(return_url.to_string()).await?;
        let return_host = ctx.trusted_host_header(req);

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
