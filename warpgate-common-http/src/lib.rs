pub mod auth;
pub mod errors;
pub mod ext;
pub mod internal_page;
mod keepalive;
pub mod logging;
mod request;

pub use auth::{AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization};
pub use keepalive::{SessionKeepalive, SessionKeepaliveGuard};
use poem::Request;
use subtle::ConstantTimeEq;
use warpgate_common::Secret;
pub use warpgate_common::http_headers::{
    X_WARPGATE_CLUSTER_CLIENT_IP, X_WARPGATE_CLUSTER_IDENTITY, X_WARPGATE_CLUSTER_TOKEN,
    X_WARPGATE_TOKEN,
};

/// True if the request carries a valid cluster token, i.e. it was forwarded by
/// a peer node. Gates every other `x-warpgate-cluster-*` header.
pub fn is_cluster_peer_request(req: &Request, cluster_token: &Secret<String>) -> bool {
    let Some(provided) = req.header(&X_WARPGATE_CLUSTER_TOKEN) else {
        return false;
    };
    // Constant-time comparison to prevent timing attacks.
    cluster_token
        .expose_secret()
        .as_bytes()
        .ct_eq(provided.as_bytes())
        .into()
}

/// The credential from the first `Authorization` header using `scheme`
/// (compared case-insensitively, as RFC 7235 requires).
pub fn authorization_token<'a>(req: &'a Request, scheme: &str) -> Option<&'a str> {
    req.headers()
        .get_all(poem::http::header::AUTHORIZATION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|v| {
            v.split_once(' ')
                .filter(|(s, _)| s.eq_ignore_ascii_case(scheme))
                .map(|(_, token)| token)
        })
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

/// [`WARPGATE_CSP`] with a single-use nonce added to `script-src`, for a page
/// that must run one inline script under the strict policy (the SSO POST
/// redirect interstitial). The same nonce must appear on the `<script>` tag.
pub fn warpgate_csp_with_script_nonce(nonce: &str) -> String {
    WARPGATE_CSP.replace(
        "script-src 'self';",
        &format!("script-src 'self' 'nonce-{nonce}';"),
    )
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
