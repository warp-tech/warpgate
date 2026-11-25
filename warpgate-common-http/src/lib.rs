pub mod auth;
pub mod cluster_tls;
pub mod errors;
pub mod ext;
pub mod internal_page;
mod keepalive;
pub mod logging;
pub mod mtls_acceptor;
mod request;

use std::time::Duration;

pub use auth::{AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization};
use bytes::{Bytes, BytesMut};
pub use cluster_tls::{ClusterPeer, cluster_peer, cluster_peer_extension, is_cluster_peer_request};
use futures::StreamExt;
use futures::stream::BoxStream;
pub use keepalive::{SessionKeepalive, SessionKeepaliveGuard};
use poem::error::ReadBodyError;
use poem::http::{HeaderMap, HeaderName, HeaderValue, header};
use poem::{Body, Request};
use warpgate_common::WarpgateError;
pub use warpgate_common::http_headers::{
    X_WARPGATE_CLUSTER_CLIENT_IP, X_WARPGATE_CLUSTER_IDENTITY, X_WARPGATE_CLUSTER_IDENTITY_TOKEN,
    X_WARPGATE_CLUSTER_NODE, X_WARPGATE_TOKEN,
};

const BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);
pub const HTTP2_MAX_CONCURRENT_STREAMS_PER_CONN: u32 = 200; // hyper default = 200, poem = unlimited

pub async fn read_body_limited_with_timeout(
    headers: &HeaderMap,
    body: Body,
    limit: usize,
) -> Result<Bytes, WarpgateError> {
    if let Some(declared) = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        && declared > limit
    {
        return Err(WarpgateError::RequestBodyTooLarge);
    }
    tokio::time::timeout(BODY_READ_TIMEOUT, body.into_bytes_limit(limit))
        .await
        .map_err(|_| WarpgateError::RequestBodyTimeout)?
        .map_err(|error| match error {
            ReadBodyError::PayloadTooLarge => WarpgateError::RequestBodyTooLarge,
            error => WarpgateError::InvalidRequest(format!("reading request body: {error}")),
        })
}

/// The `Accept-Encoding` to send upstream when the response body is forwarded
/// to the client still encoded: the client's own, or `identity` if it sent
/// none, so the upstream never picks an encoding the client didn't offer.
pub fn passthrough_accept_encoding(headers: &HeaderMap) -> HeaderValue {
    headers
        .get(header::ACCEPT_ENCODING)
        .cloned()
        .unwrap_or(HeaderValue::from_static("identity"))
}

pub enum UpstreamBody {
    Buffered(Bytes),
    /// Yields the whole body, starting from its first byte.
    Streamed(BoxStream<'static, reqwest::Result<Bytes>>),
}

/// Buffers a response body of at most `limit` bytes. A longer body is returned
/// as a stream that starts with the bytes already read, so at most `limit`
/// bytes plus one chunk are held in memory.
pub async fn buffer_response(
    mut response: reqwest::Response,
    limit: usize,
) -> reqwest::Result<UpstreamBody> {
    let mut head = BytesMut::new();
    while let Some(chunk) = response.chunk().await? {
        if head.len().saturating_add(chunk.len()) > limit {
            let read = futures::stream::iter([Ok(head.freeze()), Ok(chunk)]);
            return Ok(UpstreamBody::Streamed(
                read.chain(response.bytes_stream()).boxed(),
            ));
        }
        head.extend_from_slice(&chunk);
    }
    Ok(UpstreamBody::Buffered(head.freeze()))
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

/// Adds the baseline security headers to a Warpgate-generated response,
/// keeping any value the response already carries (e.g. a custom CSP).
///
/// Never apply this to proxied target responses: it would override the
/// upstream application's own policy.
pub fn insert_security_headers(headers: &mut HeaderMap) {
    fn insert_if_absent(headers: &mut HeaderMap, name: HeaderName, value: &'static str) {
        if !headers.contains_key(&name) {
            headers.insert(name, HeaderValue::from_static(value));
        }
    }

    insert_if_absent(headers, header::CONTENT_SECURITY_POLICY, WARPGATE_CSP);
    // Prevent MIME type sniffing - not covered by CSP.
    insert_if_absent(headers, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    // Don't leak Warpgate URLs (which may contain target names or tickets)
    // to third-party origins.
    insert_if_absent(headers, header::REFERRER_POLICY, "same-origin");
    // Legacy clickjacking protection for user agents that predate the CSP
    // `frame-ancestors` directive, which takes precedence when both are present.
    insert_if_absent(headers, header::X_FRAME_OPTIONS, "SAMEORIGIN");
}

#[cfg(test)]
mod tests {
    use futures::TryStreamExt;

    use super::*;

    #[test]
    fn passthrough_accept_encoding_defaults_to_identity() {
        let mut headers = HeaderMap::new();
        assert_eq!(passthrough_accept_encoding(&headers), "identity");
        headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("br, gzip"),
        );
        assert_eq!(passthrough_accept_encoding(&headers), "br, gzip");
    }

    /// With `ends` unset, the body stalls forever after the last chunk.
    fn response_of(chunks: &[&'static str], ends: bool) -> reqwest::Response {
        let chunks = futures::stream::iter(
            chunks
                .iter()
                .map(|chunk| Ok::<_, std::io::Error>(Bytes::from_static(chunk.as_bytes())))
                .collect::<Vec<_>>(),
        );
        poem::http::Response::new(if ends {
            reqwest::Body::wrap_stream(chunks)
        } else {
            reqwest::Body::wrap_stream(chunks.chain(futures::stream::pending()))
        })
        .into()
    }

    #[tokio::test]
    async fn body_within_the_limit_is_buffered() {
        let body = buffer_response(response_of(&["ab", "cde"], true), 5)
            .await
            .unwrap();
        let UpstreamBody::Buffered(body) = body else {
            panic!("a body no longer than the limit must be buffered");
        };
        assert_eq!(body, "abcde");
    }

    #[tokio::test]
    async fn body_over_the_limit_is_streamed_whole() {
        let body = buffer_response(response_of(&["ab", "cd", "ef", "gh"], true), 5)
            .await
            .unwrap();
        let UpstreamBody::Streamed(body) = body else {
            panic!("a body longer than the limit must not be buffered");
        };
        let chunks: Vec<Bytes> = body.try_collect().await.unwrap();
        assert_eq!(chunks.concat(), b"abcdefgh");
    }

    #[tokio::test]
    async fn body_is_not_read_past_the_limit() {
        // The body never ends, so reading on past the limit would hang.
        let body = tokio::time::timeout(
            Duration::from_secs(5),
            buffer_response(response_of(&["ab", "cd", "ef"], false), 3),
        )
        .await
        .expect("must hand the body over once it exceeds the limit")
        .unwrap();
        let UpstreamBody::Streamed(body) = body else {
            panic!("a body longer than the limit must not be buffered");
        };
        let chunks: Vec<Bytes> = body.take(3).try_collect().await.unwrap();
        assert_eq!(chunks.concat(), b"abcdef");
    }

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
