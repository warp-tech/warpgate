use cookie::Cookie;
use http::uri::Scheme;
use poem::web::Data;
use poem::{Endpoint, FromRequest, IntoResponse, Middleware, Request, Response};
use warpgate_common_http::auth::UnauthenticatedRequestContext;

use crate::common::{SESSION_COOKIE_NAME, is_localhost_host};

#[derive(Clone)]
pub struct CookieHostMiddleware {
    base_domain: Option<String>,
}

impl CookieHostMiddleware {
    /// If `base_domain` is Some(".example.com"), the session cookie will be
    /// scoped to that domain (works across subdomains). If None, it falls
    /// back to the request host (previous behavior).
    pub const fn new(base_domain: Option<String>) -> Self {
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

fn is_strict_parent(base_domain: &str, host: &str) -> bool {
    let base = base_domain.trim_start_matches('.');
    host.ends_with(&format!(".{base}"))
}

impl<E: Endpoint> Endpoint for CookieHostMiddlewareEndpoint<E> {
    type Output = Response;

    async fn call(&self, req: Request) -> poem::Result<Self::Output> {
        let ctx = Data::<&UnauthenticatedRequestContext>::from_request_without_body(&req).await?;
        let host = ctx.trusted_hostname(&req);
        let is_https = ctx.trusted_proto(&req) == Scheme::HTTPS;

        let mut resp = self.inner.call(req).await?.into_response();

        // Only rewrite the session cookie domain when:
        //   - the Host header is absent (unknown origin) and a base domain is configured, or
        //   - the host is localhost (unset domain to scope to exact host), or
        //   - base_domain is a strict DNS parent of the current host.
        //
        // `target_domain` is `Some(Some(d))` → set domain to d,
        //                    `Some(None)`    → unset domain (localhost),
        //                    `None`          → skip rewrite entirely.
        let target_domain: Option<Option<String>> = match host.as_deref() {
            None => self.base_domain.as_ref().map(|b| Some(b.clone())),
            Some(h) if is_localhost_host(h) => Some(None),
            Some(h) => self.base_domain.as_ref().and_then(|base| {
                if is_strict_parent(base, h) {
                    Some(Some(base.clone()))
                } else {
                    None
                }
            }),
        };

        let Some(target_domain) = target_domain else {
            return Ok(resp);
        };

        // Extract all Set-Cookie headers for modification
        let cookie_values: Vec<String> = {
            let headers = resp.headers();
            headers
                .get_all(http::header::SET_COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .map(std::string::ToString::to_string)
                .collect()
        };

        // Use the cookie crate to parse and modify cookies properly
        let mut modified_session_cookie: Option<String> = None;
        for cookie_str in &cookie_values {
            if let Ok(mut cookie) = Cookie::parse(cookie_str)
                && cookie.name() == SESSION_COOKIE_NAME
            {
                // Set or remove Domain attribute using cookie crate methods
                if let Some(ref domain) = target_domain {
                    cookie.set_domain(domain.clone());
                } else {
                    // For localhost/127.0.0.1, omit Domain attribute since browsers won't send cookies with a different domain
                    cookie.unset_domain();
                }

                // Add Secure and SameSite=None for HTTPS (required for cross-site cookies)
                if is_https {
                    cookie.set_secure(true);
                    cookie.set_same_site(cookie::SameSite::None);
                }

                modified_session_cookie = Some(cookie.to_string());
                tracing::debug!(
                    "CookieHostMiddleware: Modified cookie - domain={:?}, is_https={}",
                    target_domain,
                    is_https
                );
                break;
            }
        }

        if modified_session_cookie.is_none() {
            tracing::debug!(
                "CookieHostMiddleware: No session cookie found in {} cookie(s)",
                cookie_values.len()
            );
        }

        // Replace Set-Cookie headers: modified session cookie + other cookies unchanged
        if let Some(modified_cookie) = modified_session_cookie {
            let headers = resp.headers_mut();
            headers.remove(http::header::SET_COOKIE);
            if let Ok(header_value) = modified_cookie.parse::<http::HeaderValue>() {
                headers.append(http::header::SET_COOKIE, header_value);
            }
            for cookie_str in &cookie_values {
                if let Ok(cookie) = Cookie::parse(cookie_str) {
                    if cookie.name() != SESSION_COOKIE_NAME {
                        if let Ok(header_value) = cookie_str.parse::<http::HeaderValue>() {
                            headers.append(http::header::SET_COOKIE, header_value);
                        }
                    }
                }
            }
        }

        Ok(resp)
    }
}
