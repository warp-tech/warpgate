use poem_openapi::auth::Bearer;
use poem_openapi::{OpenApi, SecurityScheme};

mod known_hosts_detail;
mod known_hosts_list;
mod logs;
mod pagination;
pub mod recordings_detail;
mod roles;
mod sessions_detail;
pub mod sessions_list;
mod ssh_keys;
mod targets;
mod tickets_detail;
mod tickets_list;
mod users;

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
        Api,
    )
}
