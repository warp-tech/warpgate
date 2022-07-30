use poem::web::Data;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Enum, Object, OpenApi};
use warpgate_common::Services;
use warpgate_sso::SsoProviderConfig;

pub struct Api;

#[derive(Enum)]
pub enum SsoProviderKind {
    Google,
    Custom,
}

#[derive(Object)]
pub struct SsoProviderDescription {
    pub label: String,
    pub kind: SsoProviderKind,
}

#[derive(ApiResponse)]
enum GetSsoProvidersResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<SsoProviderDescription>>),
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
        providers.sort_by(|a, b| a.name().cmp(&b.name()));
        Ok(GetSsoProvidersResponse::Ok(Json(
            providers
                .into_iter()
                .map(|p| SsoProviderDescription {
                    label: p.label().clone(),
                    kind: match p {
                        SsoProviderConfig::Google { .. } => SsoProviderKind::Google,
                        SsoProviderConfig::Custom { .. } => SsoProviderKind::Custom,
                    },
                })
                .collect(),
        )))
    }
}
