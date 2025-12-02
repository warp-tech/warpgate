use poem_openapi::OpenApi;

mod known_hosts_detail;
mod known_hosts_list;
mod ldap_servers;
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
mod target_groups;
mod targets;
mod tickets_detail;
mod tickets_list;
pub mod users;

pub use warpgate_common::api::AnySecurityScheme;

pub fn get() -> impl OpenApi {
    // The arrangement of brackets here is simply due to
    // the limited number of `impl OpenApi for (T1, T2, ...)` overloads
    // and has no semantic meaning
    (
        (
            (sessions_list::Api, sessions_detail::Api),
            recordings_detail::Api,
            (roles::ListApi, roles::DetailApi),
            (tickets_list::Api, tickets_detail::Api),
            (known_hosts_list::Api, known_hosts_detail::Api),
            ssh_keys::Api,
            logs::Api,
            (targets::ListApi, targets::DetailApi, targets::RolesApi),
            (target_groups::ListApi, target_groups::DetailApi),
            (users::ListApi, users::DetailApi, users::RolesApi),
            (
                password_credentials::ListApi,
                password_credentials::DetailApi,
            ),
        ),
        (
            (sso_credentials::ListApi, sso_credentials::DetailApi),
            (
                public_key_credentials::ListApi,
                public_key_credentials::DetailApi,
            ),
            (otp_credentials::ListApi, otp_credentials::DetailApi),
            (
                ldap_servers::ListApi,
                ldap_servers::DetailApi,
                ldap_servers::QueryApi,
            ),
            parameters::Api,
            ssh_connection_test::Api,
        ),
    )
}
