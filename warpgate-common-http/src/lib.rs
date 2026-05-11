pub mod auth;
pub mod ext;
pub mod logging;

pub use auth::{AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization};
use poem::http::HeaderName;

pub static X_WARPGATE_TOKEN: HeaderName = HeaderName::from_static("x-warpgate-token");
