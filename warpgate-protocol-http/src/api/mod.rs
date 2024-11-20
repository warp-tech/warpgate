use poem_openapi::OpenApi;

pub mod auth;
mod common;
pub mod info;
pub mod sso_provider_detail;
pub mod sso_provider_list;
pub mod targets_list;
mod profile;

pub fn get() -> impl OpenApi {
    (
        auth::Api,
        info::Api,
        targets_list::Api,
        sso_provider_list::Api,
        sso_provider_detail::Api,
        profile::Api,
    )
}
