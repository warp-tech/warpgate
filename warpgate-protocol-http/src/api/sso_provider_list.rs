use poem::session::Session;
use poem::web::Data;
use poem_openapi::param::Query;
use poem_openapi::payload::{Json, Response};
use poem_openapi::{ApiResponse, Enum, Object, OpenApi};
use tracing::*;
use warpgate_common::Services;
use warpgate_sso::{SsoInternalProviderConfig, SsoLoginRequest};

use crate::api::sso_provider_detail::SSO_REQUEST_SESSION_KEY;

pub struct Api;

#[derive(Enum)]
pub enum SsoProviderKind {
    Google,
    Custom,
}

#[derive(Object)]
pub struct SsoProviderDescription {
    pub name: String,
    pub label: String,
    pub kind: SsoProviderKind,
}

#[derive(ApiResponse)]
enum GetSsoProvidersResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<SsoProviderDescription>>),
}

#[allow(clippy::large_enum_variant)]
#[derive(ApiResponse)]
enum ReturnToSsoResponse {
    #[oai(status = 307)]
    Ok,
    #[oai(status = 400)]
    BadRequest,
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/sso/providers",
        method = "get",
        operation_id = "get_sso_providers"
    )]
    async fn api_get_all_sso_providers(
        &self,
        services: Data<&Services>,
    ) -> poem::Result<GetSsoProvidersResponse> {
        let mut providers = services.config.lock().await.store.sso_providers.clone();
        providers.sort_by(|a, b| a.label().cmp(&b.label()));
        Ok(GetSsoProvidersResponse::Ok(Json(
            providers
                .into_iter()
                .map(|p| SsoProviderDescription {
                    name: p.name.clone(),
                    label: p.label().to_string(),
                    kind: match p.provider {
                        SsoInternalProviderConfig::Google { .. } => SsoProviderKind::Google,
                        SsoInternalProviderConfig::Custom { .. } => SsoProviderKind::Custom,
                    },
                })
                .collect(),
        )))
    }

    #[oai(path = "/sso/return", method = "get", operation_id = "return_to_sso")]
    async fn api_return_to_sso(
        &self,
        session: &Session,
        code: Query<Option<String>>,
    ) -> poem::Result<Response<ReturnToSsoResponse>> {
        let Some(request) = session.get::<SsoLoginRequest>(SSO_REQUEST_SESSION_KEY) else {
            warn!("Not in an active SSO process");
            return Ok(Response::new(ReturnToSsoResponse::BadRequest));
        };

        let Some(ref code) = *code else {
            warn!("No authorization code in the return URL request");
            return Ok(Response::new(ReturnToSsoResponse::BadRequest));
        };

        let response = request
            .verify_code((*code).clone())
            .await
            .map_err(poem::error::InternalServerError)?;

        println!("{:?}", response);

        Ok(Response::new(ReturnToSsoResponse::Ok))
    }
}
