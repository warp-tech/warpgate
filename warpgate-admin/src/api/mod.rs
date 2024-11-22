use poem_openapi::OpenApi;

mod known_hosts_detail;
mod known_hosts_list;
mod logs;
mod pagination;
mod password_credentials;
pub mod recordings_detail;
mod roles;
mod sessions_detail;
pub mod sessions_list;
mod ssh_keys;
mod sso_credentials;
mod targets;
mod tickets_detail;
mod tickets_list;
mod users;

pub fn get() -> impl OpenApi {
    (
        sessions_list::Api,
        sessions_detail::Api,
        recordings_detail::Api,
        roles::ListApi,
        roles::DetailApi,
        (targets::ListApi, targets::DetailApi, targets::RolesApi),
        (users::ListApi, users::DetailApi, users::RolesApi),
        tickets_list::Api,
        tickets_detail::Api,
        known_hosts_list::Api,
        known_hosts_detail::Api,
        ssh_keys::Api,
        logs::Api,
        (
            password_credentials::ListApi,
            password_credentials::DetailApi,
        ),
        (sso_credentials::ListApi, sso_credentials::DetailApi),
    )
}
