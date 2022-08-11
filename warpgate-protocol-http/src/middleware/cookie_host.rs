use async_trait::async_trait;
use http::header::Entry;
use poem::web::cookie::Cookie;
use poem::{Endpoint, IntoResponse, Middleware, Request, Response};

use crate::common::SESSION_COOKIE_NAME;

pub struct CookieHostMiddleware {}

impl CookieHostMiddleware {
    pub fn new() -> Self {
        Self {}
    }
}

pub struct CookieHostMiddlewareEndpoint<E: Endpoint> {
    inner: E,
}

impl<E: Endpoint> Middleware<E> for CookieHostMiddleware {
    type Output = CookieHostMiddlewareEndpoint<E>;

    fn transform(&self, inner: E) -> Self::Output {
        CookieHostMiddlewareEndpoint { inner }
    }
}

#[async_trait]
impl<E: Endpoint> Endpoint for CookieHostMiddlewareEndpoint<E> {
    type Output = Response;

    async fn call(&self, req: Request) -> poem::Result<Self::Output> {
        let host = req.original_uri().host().map(|x| x.to_string());

        let mut resp = self.inner.call(req).await?.into_response();

        if let Some(host) = host {
            if let Entry::Occupied(mut entry) = resp.headers_mut().entry(http::header::SET_COOKIE) {
                if let Ok(cookie_str) = entry.get().to_str() {
                    if let Ok(mut cookie) = Cookie::parse(cookie_str) {
                        if cookie.name() == SESSION_COOKIE_NAME {
                            cookie.set_domain(host);
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
