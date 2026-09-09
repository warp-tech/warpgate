use http::StatusCode;
use poem::IntoResponse;
use tracing::error;

use crate::internal_page::internal_page;

pub fn error_page(e: &poem::Error) -> impl IntoResponse {
    error!("{:?}", e);
    internal_page("Request failed", &e.to_string(), None, None).with_status(StatusCode::BAD_GATEWAY)
}
