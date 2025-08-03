use poem_openapi::OpenApi;

mod certificate_credentials;
mod known_hosts_detail;
mod known_hosts_list;
mod logs;
mod otp_credentials;
mod pagination;
mod parameters;
mod password_credentials;
mod public_key_credentials;
pub mod recordings_detail;
mod roles;
mod sessions_detail;
pub mod sessions_list;
mod ssh_connection_test;
mod ssh_keys;
mod sso_credentials;
mod targets;
mod tickets_detail;
mod tickets_list;
pub mod users;

pub use warpgate_common::api::AnySecurityScheme;

pub fn get() -> impl OpenApi {
    (
        (sessions_list::Api, sessions_detail::Api),
        recordings_detail::Api,
        (roles::ListApi, roles::DetailApi),
        (tickets_list::Api, tickets_detail::Api),
        (known_hosts_list::Api, known_hosts_detail::Api),
        ssh_keys::Api,
        logs::Api,
        (targets::ListApi, targets::DetailApi, targets::RolesApi),
        (users::ListApi, users::DetailApi, users::RolesApi),
        (
            password_credentials::ListApi,
            password_credentials::DetailApi,
        ),
        (sso_credentials::ListApi, sso_credentials::DetailApi),
        (
            public_key_credentials::ListApi,
            public_key_credentials::DetailApi,
        ),
        (
            certificate_credentials::ListApi,
            certificate_credentials::DetailApi,
        ),
        (otp_credentials::ListApi, otp_credentials::DetailApi),
        parameters::Api,
        ssh_connection_test::Api,
    )
}
