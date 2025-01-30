mod api;
use poem_openapi::OpenApiService;
use regex::Regex;

#[allow(clippy::unwrap_used)]
pub fn main() {
    let api_service =
        OpenApiService::new(api::get(), "Warpgate Web Admin", env!("CARGO_PKG_VERSION"))
            .server("/@warpgate/admin/api");

    let spec = api_service.spec();
    let re = Regex::new(r"PaginatedResponse<(?P<name>\w+)>").unwrap();
    let spec = re.replace_all(&spec, "Paginated$name");

    println!("{spec}");
}
