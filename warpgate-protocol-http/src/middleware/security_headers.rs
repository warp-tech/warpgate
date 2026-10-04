use poem::http::{HeaderMap, HeaderName, HeaderValue, header};
use poem::{Endpoint, IntoResponse, Middleware, Request, Response};
pub use warpgate_common_http::{WARPGATE_CSP, WARPGATE_PLAYGROUND_CSP};

/// Adds baseline security headers to Warpgate's own responses.
///
/// Every header is only set when absent, so individual endpoints (e.g. the
/// OpenAPI playground or the admin document) can still supply their own value.
///
/// This must only wrap Warpgate-served endpoints, never proxied target
/// traffic, as it would otherwise override the upstream application's policy.
#[derive(Clone)]
pub struct SecurityHeadersMiddleware;

impl<E: Endpoint> Middleware<E> for SecurityHeadersMiddleware {
    type Output = SecurityHeadersEndpoint<E>;

    fn transform(&self, inner: E) -> Self::Output {
        SecurityHeadersEndpoint { inner }
    }
}

pub struct SecurityHeadersEndpoint<E: Endpoint> {
    inner: E,
}

fn insert_if_absent(headers: &mut HeaderMap, name: HeaderName, value: &'static str) {
    if !headers.contains_key(&name) {
        headers.insert(name, HeaderValue::from_static(value));
    }
}

impl<E: Endpoint> Endpoint for SecurityHeadersEndpoint<E> {
    type Output = Response;

    async fn call(&self, req: Request) -> poem::Result<Self::Output> {
        let mut resp = self.inner.call(req).await?.into_response();
        let headers = resp.headers_mut();

        insert_if_absent(headers, header::CONTENT_SECURITY_POLICY, WARPGATE_CSP);
        // Prevent MIME type sniffing - not covered by CSP.
        insert_if_absent(headers, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
        // Don't leak Warpgate URLs (which may contain target names or tickets)
        // to third-party origins.
        insert_if_absent(headers, header::REFERRER_POLICY, "same-origin");
        // Legacy clickjacking protection. Modern browsers use the CSP
        // `frame-ancestors 'self'` directive instead and ignore this header
        // when both are present; it is kept for older user agents only.
        insert_if_absent(headers, header::X_FRAME_OPTIONS, "SAMEORIGIN");

        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use poem::endpoint::make_sync;
    use poem::{EndpointExt, Request, Response};

    use super::*;

    fn assert_baseline_headers(resp: &Response) {
        assert_eq!(
            resp.headers().get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff"
        );
        assert_eq!(
            resp.headers().get(header::REFERRER_POLICY).unwrap(),
            "same-origin"
        );
        assert_eq!(
            resp.headers().get(header::X_FRAME_OPTIONS).unwrap(),
            "SAMEORIGIN"
        );
    }

    #[tokio::test]
    async fn adds_strict_csp_when_absent() {
        let ep = make_sync(|_| Response::builder().finish()).with(SecurityHeadersMiddleware);
        let resp = ep.call(Request::default()).await.unwrap();
        assert_eq!(
            resp.headers().get(header::CONTENT_SECURITY_POLICY).unwrap(),
            WARPGATE_CSP
        );
        assert_baseline_headers(&resp);
    }

    #[tokio::test]
    async fn preserves_existing_csp() {
        // Endpoints such as the OpenAPI playground set their own relaxed policy,
        // which must not be overwritten by the strict default.
        let ep = make_sync(|_| {
            Response::builder()
                .header(header::CONTENT_SECURITY_POLICY, WARPGATE_PLAYGROUND_CSP)
                .finish()
        })
        .with(SecurityHeadersMiddleware);
        let resp = ep.call(Request::default()).await.unwrap();
        assert_eq!(
            resp.headers().get(header::CONTENT_SECURITY_POLICY).unwrap(),
            WARPGATE_PLAYGROUND_CSP
        );
        // The remaining headers must still be applied alongside a custom CSP.
        assert_baseline_headers(&resp);
    }

    #[tokio::test]
    async fn preserves_existing_security_headers() {
        let ep = make_sync(|_| {
            Response::builder()
                .header(header::X_FRAME_OPTIONS, "DENY")
                .header(header::REFERRER_POLICY, "no-referrer")
                .finish()
        })
        .with(SecurityHeadersMiddleware);
        let resp = ep.call(Request::default()).await.unwrap();
        assert_eq!(resp.headers().get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
        assert_eq!(
            resp.headers().get(header::REFERRER_POLICY).unwrap(),
            "no-referrer"
        );
        assert_eq!(
            resp.headers().get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff"
        );
    }
}
