use poem::{Endpoint, IntoResponse, Middleware, Request, Response};
use warpgate_common_http::insert_security_headers;

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

/// Applies [`insert_security_headers`] to successful responses. Must only wrap
/// Warpgate-served endpoints; errors get the same headers from `render_errors`.
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

impl<E: Endpoint> Endpoint for SecurityHeadersEndpoint<E> {
    type Output = Response;

    async fn call(&self, req: Request) -> poem::Result<Self::Output> {
        let mut resp = self.inner.call(req).await?.into_response();
        insert_security_headers(resp.headers_mut());
        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use poem::endpoint::make_sync;
    use poem::http::header;
    use poem::{EndpointExt, Request, Response};
    use warpgate_common_http::{WARPGATE_CSP, WARPGATE_PLAYGROUND_CSP};

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
