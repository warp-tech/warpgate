use poem_openapi::auth::Bearer;
use poem_openapi::{OpenApi, SecurityScheme};

mod auth;
mod info;
mod sso_provider_detail;
mod sso_provider_list;
mod targets_list;
mod tokens_detail;
mod tokens_list;

#[derive(SecurityScheme)]
#[oai(type = "bearer")]
pub(crate) struct TokenAuth(Bearer);

pub struct Api;

#[OpenApi]
impl Api {
    #[oai(path = "/__", method = "get", operation_id = "_ignore_me")]
    async fn _hidden(
        &self,
        _auth: TokenAuth, // only needed once for the security schema to be included in the spec
    ) -> poem::Result<()> {
        Ok(())
    }
}

pub fn get() -> impl OpenApi {
    (
        auth::Api,
        info::Api,
        targets_list::Api,
        sso_provider_list::Api,
        sso_provider_detail::Api,
        tokens_list::Api,
        tokens_detail::Api,
        Api,
    )
}
