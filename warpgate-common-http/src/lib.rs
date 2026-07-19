pub mod auth;
pub mod ext;
pub mod logging;
mod request;

pub use auth::{AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization};
use poem::http::HeaderName;

pub static X_WARPGATE_TOKEN: HeaderName = HeaderName::from_static("x-warpgate-token");
pub static X_WARPGATE_CLUSTER_TOKEN: HeaderName =
    HeaderName::from_static("x-warpgate-cluster-token");
/// Carries the forwarding node's own [`RequestAuthorization`] alongside
/// [`X_WARPGATE_CLUSTER_TOKEN`]. Required on every cluster-forwarded request.
pub static X_WARPGATE_CLUSTER_ACTOR: HeaderName =
    HeaderName::from_static("x-warpgate-cluster-actor");

/// Encodes an authorization for [`X_WARPGATE_CLUSTER_ACTOR`].
///
/// Base64 because a header value must be visible ASCII and a username need not
/// be — it is an encoding, not a protection; the cluster token is what makes
/// the claim trustworthy.
pub fn encode_cluster_actor(auth: &RequestAuthorization) -> Result<String, serde_json::Error> {
    Ok(data_encoding::BASE64.encode(serde_json::to_string(auth)?.as_bytes()))
}

/// Inverse of [`encode_cluster_actor`]; `None` for anything unreadable.
pub fn decode_cluster_actor(value: &str) -> Option<RequestAuthorization> {
    let bytes = data_encoding::BASE64.decode(value.as_bytes()).ok()?;
    serde_json::from_slice(&bytes).ok()
}

// style-src unsafe-inline for Svelte
// img-src data: for TOTP codes
pub const WARPGATE_CSP: &str = "default-src 'self'; \
script-src 'self'; \
style-src 'self' 'unsafe-inline'; \
img-src 'self' data:; \
font-src 'self' data:; \
connect-src 'self'; \
frame-ancestors 'self'; \
base-uri 'self'; \
form-action 'self'; \
object-src 'none'";

/// [`WARPGATE_CSP`] with an extra origin allow-listed in `connect-src`, for the
/// admin document whose recording player fetches directly from an external S3
/// bucket. `None` returns the default policy unchanged.
pub fn warpgate_csp_with_connect_src(extra_origin: Option<&str>) -> String {
    match extra_origin {
        Some(origin) => WARPGATE_CSP.replace(
            "connect-src 'self';",
            &format!("connect-src 'self' {origin};"),
        ),
        None => WARPGATE_CSP.to_string(),
    }
}

pub const WARPGATE_PLAYGROUND_CSP: &str = "default-src 'self'; \
script-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com; \
style-src 'self' 'unsafe-inline' https://unpkg.com https://fonts.googleapis.com; \
font-src 'self' data: https://unpkg.com https://fonts.gstatic.com; \
img-src 'self' data: https://unpkg.com; \
connect-src 'self' https://unpkg.com; \
object-src 'none'";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_src_extension() {
        assert_eq!(warpgate_csp_with_connect_src(None), WARPGATE_CSP);

        let csp = warpgate_csp_with_connect_src(Some("https://bucket.s3.eu-west-1.amazonaws.com"));
        assert!(csp.contains("connect-src 'self' https://bucket.s3.eu-west-1.amazonaws.com;"));
        // Other directives are untouched.
        assert!(csp.contains("default-src 'self';"));
        assert!(csp.contains("object-src 'none'"));
    }
}
