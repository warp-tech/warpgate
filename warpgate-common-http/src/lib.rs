pub mod auth;
pub mod ext;
pub mod logging;
mod request;

pub use auth::{AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization};
use poem::http::HeaderName;

pub static X_WARPGATE_TOKEN: HeaderName = HeaderName::from_static("x-warpgate-token");
