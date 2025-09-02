use http::header::Entry;
use poem::web::cookie::Cookie;
use poem::{Endpoint, IntoResponse, Middleware, Request, Response};

use crate::common::SESSION_COOKIE_NAME;

#[derive(Clone)]
pub struct CookieHostMiddleware {
    base_domain: Option<String>,
}

impl CookieHostMiddleware {
    /// If `base_domain` is Some(".example.com"), the session cookie will be
    /// scoped to that domain (works across subdomains). If None, it falls
    /// back to the request host (previous behavior).
    pub fn new(base_domain: Option<String>) -> Self {
        Self { base_domain }
    }
}

pub struct CookieHostMiddlewareEndpoint<E: Endpoint> {
    inner: E,
    base_domain: Option<String>,
}

impl<E: Endpoint> Middleware<E> for CookieHostMiddleware {
    type Output = CookieHostMiddlewareEndpoint<E>;

    fn transform(&self, inner: E) -> Self::Output {
        CookieHostMiddlewareEndpoint {
            inner,
            base_domain: self.base_domain.clone(),
        }
    }
}

impl<E: Endpoint> Endpoint for CookieHostMiddlewareEndpoint<E> {
    type Output = Response;

    async fn call(&self, req: Request) -> poem::Result<Self::Output> {
        // Capture the request host before consuming `req`
        let host = req.original_uri().host().map(|x| x.to_string());

        let mut resp = self.inner.call(req).await?.into_response();

        if let Some(host) = host {
            if let Entry::Occupied(mut entry) = resp.headers_mut().entry(http::header::SET_COOKIE) {
                if let Ok(cookie_str) = entry.get().to_str() {
                    if let Ok(mut cookie) = Cookie::parse(cookie_str) {
                        if cookie.name() == SESSION_COOKIE_NAME {
                            if let Some(ref base) = self.base_domain {
                                // Preferred: scope cookie to parent domain for all subdomains
                                cookie.set_domain(base);
                            } else {
                                // Fallback: preserve previous behavior (use request host)
                                cookie.set_domain(&host);
                            }
                            if let Ok(value) = cookie.to_string().parse() {
                                entry.insert(value);
                            }
                        }
                    }
                }
            }
        }
        Ok(resp)
    }
}

