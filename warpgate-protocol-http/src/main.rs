#![feature(type_alias_impl_trait, let_else, try_blocks)]
mod api;
use regex::Regex;
mod common;
mod session;
mod session_handle;
use poem_openapi::OpenApiService;

#[allow(clippy::unwrap_used)]
pub fn main() {
    let api_service = OpenApiService::new(
        api::get(),
        "Warpgate HTTP proxy",
        env!("CARGO_PKG_VERSION"),
    )
    .server("/@warpgate/api");

    let spec = api_service.spec();
    let re = Regex::new(r"PaginatedResponse<(?P<name>\w+)>").unwrap();
    let spec = re.replace_all(&spec, "Paginated$name");

    println!("{}", spec);
}
