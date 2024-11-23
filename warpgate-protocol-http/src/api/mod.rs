use poem_openapi::auth::ApiKey;
use poem_openapi::{OpenApi, SecurityScheme};

pub mod auth;
mod common;
pub mod info;
pub mod sso_provider_detail;
pub mod sso_provider_list;
pub mod targets_list;

#[derive(SecurityScheme)]
#[oai(ty = "api_key", key_name = "X-Warpgate-Token", key_in = "header")]
#[allow(dead_code)]
pub struct TokenSecurityScheme(ApiKey);

struct StubApi;

#[OpenApi]
impl StubApi {
    #[oai(path = "/__stub__", method = "get", operation_id = "__stub__")]
    async fn stub(&self, _auth: TokenSecurityScheme) -> poem::Result<()> {
        Ok(())
    }
}

pub fn get() -> impl OpenApi {
    (
        StubApi,
        auth::Api,
        info::Api,
        targets_list::Api,
        sso_provider_list::Api,
        sso_provider_detail::Api,
    )
}
