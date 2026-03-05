use std::collections::HashSet;

use once_cell::sync::Lazy;
use poem::http::{self, HeaderName};

/// Headers that should not be forwarded to upstream when proxying HTTP requests
pub static DONT_FORWARD_HEADERS: Lazy<HashSet<HeaderName>> = Lazy::new(|| {
    #[allow(clippy::mutable_key_type)]
    let mut s = HashSet::new();
    s.insert(http::header::ACCEPT_ENCODING);
    s.insert(http::header::SEC_WEBSOCKET_EXTENSIONS);
    s.insert(http::header::SEC_WEBSOCKET_ACCEPT);
    s.insert(http::header::SEC_WEBSOCKET_KEY);
    s.insert(http::header::SEC_WEBSOCKET_VERSION);
    s.insert(http::header::UPGRADE);
    s.insert(http::header::HOST);
    s.insert(http::header::CONNECTION);
    s.insert(http::header::STRICT_TRANSPORT_SECURITY);
    s.insert(http::header::UPGRADE_INSECURE_REQUESTS);
    s
});

pub static X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
pub static X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
pub static X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
