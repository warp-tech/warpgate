#![feature(type_alias_impl_trait, let_else, try_blocks)]
mod api;
mod common;
use poem_openapi::OpenApiService;

pub fn main() {
    let api_service = OpenApiService::new(
        api::get(),
        "Warpgate HTTP proxy",
        env!("CARGO_PKG_VERSION"),
    )
    .server("/@warpgate/api");
    println!("{}", api_service.spec());
}
