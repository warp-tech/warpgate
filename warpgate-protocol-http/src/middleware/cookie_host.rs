use once_cell::sync::Lazy;
use poem::web::cookie::Cookie;
use poem::{Endpoint, IntoResponse, Middleware, Request, Response};
use regex::Regex;
use http::uri::Scheme;

use crate::common::{is_localhost_host, SESSION_COOKIE_NAME};

static DOMAIN_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r";\s*Domain=[^;]*").unwrap()
});

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

            // Parse cookies manually to modify Domain/Secure/SameSite attributes.
            // The Cookie crate doesn't easily allow modifying these and converting back to header format.
            let mut modified_session_cookie: Option<String> = None;
            for cookie_str in &cookie_values {
                if cookie_str.starts_with(&format!("{}=", SESSION_COOKIE_NAME)) {
                    // For localhost/127.0.0.1, omit Domain attribute since browsers won't send cookies with a different domain
                    let is_localhost = is_localhost_host(&host);
                    let target_domain = if is_localhost {
                        None // Omit Domain attribute for localhost - browser will scope to exact host
                    } else if let Some(ref base) = self.base_domain {
                        Some(base.clone())
                    } else {
                        Some(host.clone())
                    };

                    // Modify Domain attribute: set to base domain (for subdomain sharing) or remove for localhost
                    let mut modified = if let Some(ref domain) = target_domain {
                        if cookie_str.contains("; Domain=") {
                            DOMAIN_REGEX.replace(cookie_str, &format!("; Domain={}", domain)).to_string()
                        } else {
                            if let Some(pos) = cookie_str.find(';') {
                                format!("{}; Domain={}{}", &cookie_str[..pos], domain, &cookie_str[pos..])
                            } else {
                                format!("{}; Domain={}", cookie_str, domain)
                            }
                        }
                    } else {
                        // Remove Domain attribute for localhost (omit Domain, browser will scope to exact host)
                        if cookie_str.contains("; Domain=") {
                            let removed = DOMAIN_REGEX.replace(cookie_str, "");
                            // Clean up any trailing semicolons and whitespace
                            removed.trim_end_matches(';').trim_end().to_string()
                        } else {
                            cookie_str.clone()
                        }
                    };

                    // Add Secure and SameSite=None for HTTPS (required for cross-site cookies)
                    if is_https {
                        if !modified.contains("; Secure") && !modified.contains(";Secure") {
                            if modified.contains("; HttpOnly") {
                                modified = modified.replace("; HttpOnly", "; Secure; HttpOnly");
                            } else if modified.contains("; SameSite") {
                                modified = modified.replace("; SameSite", "; Secure; SameSite");
                            } else {
                                modified = format!("{}; Secure", modified);
                            }
                        }
                        
                        let has_samesite = modified.contains("SameSite=") || 
                                           modified.to_lowercase().contains("samesite=");
                        if !has_samesite {
                            if modified.contains("; HttpOnly") {
                                modified = modified.replace("; HttpOnly", "; SameSite=None; HttpOnly");
                            } else if modified.ends_with("; Secure") {
                                modified = format!("{}; SameSite=None", modified);
                            } else {
                                modified = format!("{}; SameSite=None", modified);
                            }
                        }
                    }

                    if self.base_domain.is_none() {
                        tracing::warn!(
                            "CookieHostMiddleware: Setting session cookie domain to request host: {} (no base domain configured). This may prevent SSO from working across subdomains. Consider setting 'external_host' in config.",
                            host
                        );
                    }

                    modified_session_cookie = Some(modified.clone());
                    tracing::debug!("CookieHostMiddleware: Modified cookie - domain={:?}, is_https={}", target_domain, is_https);
                    break;
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

