use poem_openapi::OpenApi;

pub mod auth;
pub mod info;
pub mod targets_list;

pub fn get() -> impl OpenApi {
    (auth::Api, info::Api, targets_list::Api)
}
