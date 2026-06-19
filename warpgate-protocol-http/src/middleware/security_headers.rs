use poem::http::{HeaderValue, header};
use poem::{Endpoint, IntoResponse, Middleware, Request, Response};

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

pub const WARPGATE_PLAYGROUND_CSP: &str = "default-src 'self'; \
script-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com; \
style-src 'self' 'unsafe-inline' https://unpkg.com https://fonts.googleapis.com; \
font-src 'self' data: https://unpkg.com https://fonts.gstatic.com; \
img-src 'self' data: https://unpkg.com; \
connect-src 'self' https://unpkg.com; \
object-src 'none'";

#[derive(Clone)]
pub struct ContentSecurityPolicyMiddleware;

impl<E: Endpoint> Middleware<E> for ContentSecurityPolicyMiddleware {
    type Output = ContentSecurityPolicyEndpoint<E>;

    fn transform(&self, inner: E) -> Self::Output {
        ContentSecurityPolicyEndpoint { inner }
    }
}

pub struct ContentSecurityPolicyEndpoint<E: Endpoint> {
    inner: E,
}

impl<E: Endpoint> Endpoint for ContentSecurityPolicyEndpoint<E> {
    type Output = Response;

    async fn call(&self, req: Request) -> poem::Result<Self::Output> {
        let mut resp = self.inner.call(req).await?.into_response();
        if !resp.headers().contains_key(header::CONTENT_SECURITY_POLICY) {
            resp.headers_mut().insert(
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(WARPGATE_CSP),
            );
        }
        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use poem::endpoint::make_sync;
    use poem::{EndpointExt, Request, Response};

    use super::*;

    #[tokio::test]
    async fn adds_strict_csp_when_absent() {
        let ep = make_sync(|_| Response::builder().finish()).with(ContentSecurityPolicyMiddleware);
        let resp = ep.call(Request::default()).await.unwrap();
        assert_eq!(
            resp.headers().get(header::CONTENT_SECURITY_POLICY).unwrap(),
            WARPGATE_CSP
        );
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
        .with(ContentSecurityPolicyMiddleware);
        let resp = ep.call(Request::default()).await.unwrap();
        assert_eq!(
            resp.headers().get(header::CONTENT_SECURITY_POLICY).unwrap(),
            WARPGATE_PLAYGROUND_CSP
        );
    }
}
