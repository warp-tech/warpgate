use poem_openapi::auth::ApiKey;
use poem_openapi::{OpenApi, SecurityScheme};

mod api_tokens;
pub mod auth;
mod common;
mod credentials;
pub mod info;
pub mod sso_provider_detail;
pub mod sso_provider_list;
pub mod targets_list;

#[derive(SecurityScheme)]
#[oai(ty = "api_key", key_name = "X-Warpgate-Token", key_in = "header")]
#[allow(dead_code)]
pub struct AnySecurityScheme(ApiKey);

struct StubApi;

#[OpenApi]
impl StubApi {
    #[oai(path = "/__stub__", method = "get", operation_id = "__stub__")]
    async fn stub(&self, _auth: AnySecurityScheme) -> poem::Result<()> {
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
        credentials::Api,
        api_tokens::Api,
    )
}
