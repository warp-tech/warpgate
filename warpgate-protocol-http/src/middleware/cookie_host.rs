use cookie::Cookie;
use poem::{Endpoint, IntoResponse, Middleware, Request, Response};
use http::uri::Scheme;

use crate::common::{is_localhost_host, SESSION_COOKIE_NAME};

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
        let host = req
            .header(http::header::HOST)
            .map(|h| h.split(':').next().unwrap_or(h).to_string())
            .or_else(|| req.original_uri().host().map(|x| x.to_string()));

        let scheme_https = req.original_uri().scheme() == Some(&Scheme::HTTPS);
        let header_https = req.header("x-forwarded-proto").map(|h| h == "https").unwrap_or(false);
        let is_https = scheme_https || header_https;

        let mut resp = self.inner.call(req).await?.into_response();

        if let Some(host) = host {
            // Extract all Set-Cookie headers for modification
            let cookie_values: Vec<String> = {
                let headers = resp.headers();
                headers
                    .get_all(http::header::SET_COOKIE)
                    .iter()
                    .filter_map(|v| v.to_str().ok())
                    .map(|s| s.to_string())
                    .collect()
            };

            // Use the cookie crate to parse and modify cookies properly
            let mut modified_session_cookie: Option<String> = None;
            for cookie_str in &cookie_values {
                if let Ok(mut cookie) = Cookie::parse(cookie_str) {
                    if cookie.name() == SESSION_COOKIE_NAME {
                        // For localhost/127.0.0.1, omit Domain attribute since browsers won't send cookies with a different domain
                        let is_localhost = is_localhost_host(&host);
                        let target_domain = if is_localhost {
                            None // Omit Domain attribute for localhost - browser will scope to exact host
                        } else if let Some(ref base) = self.base_domain {
                            Some(base.clone())
                        } else {
                            Some(host.clone())
                        };

                        // Set or remove Domain attribute using cookie crate methods
                        if let Some(ref domain) = target_domain {
                            cookie.set_domain(domain.clone());
                        } else {
                            // For localhost, we need to remove the domain attribute
                            // Rebuild the cookie without domain, copying all other attributes
                            let name = cookie.name().to_string();
                            let value = cookie.value().to_string();
                            let path_str = cookie.path().map(|p| p.to_string());
                            let http_only = cookie.http_only().unwrap_or(false);
                            let secure = cookie.secure().unwrap_or(false);
                            let same_site = cookie.same_site();
                            let max_age = cookie.max_age();
                            let expires = cookie.expires();

                            let mut builder = Cookie::build((name, value));

                            if let Some(p) = path_str {
                                builder = builder.path(p);
                            }
                            if http_only {
                                builder = builder.http_only(true);
                            }
                            if secure {
                                builder = builder.secure(true);
                            }
                            if let Some(same_site) = same_site {
                                builder = builder.same_site(same_site);
                            }
                            if let Some(max_age) = max_age {
                                builder = builder.max_age(max_age);
                            }
                            if let Some(expires) = expires {
                                builder = builder.expires(expires);
                            }

                            cookie = builder.build();
                        }

                        // Add Secure and SameSite=None for HTTPS (required for cross-site cookies)
                        if is_https {
                            cookie.set_secure(true);
                            cookie.set_same_site(cookie::SameSite::None);
                        }

                        if self.base_domain.is_none() {
                            tracing::warn!(
                                "CookieHostMiddleware: Setting session cookie domain to request host: {} (no base domain configured). This may prevent SSO from working across subdomains. Consider setting 'external_host' in config.",
                                host
                            );
                        }

                        modified_session_cookie = Some(cookie.to_string());
                        tracing::debug!("CookieHostMiddleware: Modified cookie - domain={:?}, is_https={}", target_domain, is_https);
                        break;
                    }
                }
            }

            if modified_session_cookie.is_none() {
                tracing::debug!("CookieHostMiddleware: No session cookie found in {} cookie(s)", cookie_values.len());
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
        }
        Ok(resp)
    }
}
