use once_cell::sync::Lazy;
use poem::web::cookie::Cookie;
use poem::{Endpoint, IntoResponse, Middleware, Request, Response};
use regex::Regex;

use crate::common::SESSION_COOKIE_NAME;

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
        // Capture the request host from Host header (more reliable than URI host when behind proxy)
        let host = req
            .header(http::header::HOST)
            .map(|h| h.split(':').next().unwrap_or(h).to_string())
            .or_else(|| req.original_uri().host().map(|x| x.to_string()));

        // Capture HTTPS status before req is moved
        // Check both URI scheme and x-forwarded-proto header (for behind proxy scenarios)
        let scheme_https = req.original_uri().scheme().map(|s| s.as_str() == "https").unwrap_or(false);
        let header_https = req.header("x-forwarded-proto").map(|h| h == "https").unwrap_or(false);
        let is_https = scheme_https || header_https;
        tracing::debug!("CookieHostMiddleware: HTTPS detection - scheme={:?}, x-forwarded-proto={:?}, is_https={}", 
            req.original_uri().scheme().map(|s| s.as_str()),
            req.header("x-forwarded-proto").map(|h| h.to_string()),
            is_https);

        let mut resp = self.inner.call(req).await?.into_response();

        if let Some(host) = host {
            // Handle all SET-COOKIE headers (there may be multiple)
            // Collect cookie values first to release the immutable borrow
            let cookie_values: Vec<String> = {
                let headers = resp.headers();
                headers
                    .get_all(http::header::SET_COOKIE)
                    .iter()
                    .filter_map(|v| v.to_str().ok())
                    .map(|s| s.to_string())
                    .collect()
            };

            tracing::debug!("CookieHostMiddleware: Found {} cookie(s), base_domain={:?}, request_host={}", 
                cookie_values.len(), self.base_domain, host);

            // Find and modify the session cookie if present
            // We manually modify the cookie string to preserve all attributes (Secure, HttpOnly, SameSite, Path, etc.)
            let mut modified_session_cookie: Option<String> = None;
            for cookie_str in &cookie_values {
                // Check if this is the session cookie by looking for the cookie name
                if cookie_str.starts_with(&format!("{}=", SESSION_COOKIE_NAME)) {
                    let original_domain = if let Ok(cookie) = Cookie::parse(cookie_str) {
                        cookie.domain().map(|d| d.to_string())
                    } else {
                        None
                    };

                    let target_domain = if let Some(ref base) = self.base_domain {
                        base.clone()
                    } else {
                        host.clone()
                    };

                    // Manually modify the domain attribute in the cookie string
                    // This preserves all other attributes (Secure, HttpOnly, SameSite, Path, Expires, etc.)
                    // For cross-subdomain cookies to work, we need SameSite=None and Secure=true
                    let mut modified = if cookie_str.contains("; Domain=") {
                        // Replace existing Domain attribute
                        DOMAIN_REGEX.replace(cookie_str, &format!("; Domain={}", target_domain)).to_string()
                    } else {
                        // Add Domain attribute after the value (before other attributes like Path, Secure, etc.)
                        // Find the first semicolon (after the value) and insert Domain there
                        if let Some(pos) = cookie_str.find(';') {
                            format!("{}; Domain={}{}", &cookie_str[..pos], target_domain, &cookie_str[pos..])
                        } else {
                            // No attributes, just add Domain
                            format!("{}; Domain={}", cookie_str, target_domain)
                        }
                    };

                    // Ensure Secure flag is set for HTTPS requests (required for cross-subdomain cookies)
                    if is_https {
                        // Ensure Secure flag is present
                        if !modified.contains("; Secure") && !modified.contains(";Secure") {
                            // Add Secure before the final attributes
                            if modified.contains("; HttpOnly") {
                                modified = modified.replace("; HttpOnly", "; Secure; HttpOnly");
                            } else if modified.contains("; SameSite") {
                                modified = modified.replace("; SameSite", "; Secure; SameSite");
                            } else {
                                modified = format!("{}; Secure", modified);
                            }
                        }
                        
                        // Ensure SameSite=None for cross-subdomain cookie sharing (required when using Domain)
                        // Check both "SameSite=" and "samesite=" (case-insensitive)
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
                            tracing::info!("CookieHostMiddleware: Added SameSite=None for cross-subdomain cookie sharing");
                        }
                    }

                    if let Some(ref base) = self.base_domain {
                        tracing::info!(
                            "CookieHostMiddleware: Setting session cookie domain to {} (was: {:?}, request host: {})",
                            base,
                            original_domain,
                            host
                        );
                    } else {
                        tracing::warn!(
                            "CookieHostMiddleware: Setting session cookie domain to request host: {} (no base domain configured). This may prevent SSO from working across subdomains. Consider setting 'external_host' in config.",
                            host
                        );
                    }

                    modified_session_cookie = Some(modified.clone());
                    tracing::info!(
                        "CookieHostMiddleware: Modified cookie - domain={}, is_https={}, cookie_preview={}...",
                        target_domain,
                        is_https,
                        if modified.len() > 100 { &modified[..100] } else { &modified }
                    );
                    tracing::debug!("CookieHostMiddleware: Full modified cookie string: {}", modified);
                    break;
                }
            }

            if modified_session_cookie.is_none() {
                tracing::debug!("CookieHostMiddleware: No session cookie found in {} cookie(s)", cookie_values.len());
            }

            // If we modified the session cookie, replace all SET-COOKIE headers
            if let Some(modified_cookie) = modified_session_cookie {
                let headers = resp.headers_mut();
                headers.remove(http::header::SET_COOKIE);
                // Add the modified session cookie
                if let Ok(header_value) = modified_cookie.parse::<http::HeaderValue>() {
                    headers.append(http::header::SET_COOKIE, header_value);
                }
                // Re-add other cookies (non-session cookies)
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

