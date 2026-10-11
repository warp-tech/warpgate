use cookie::Cookie;
use http::uri::Scheme;
use poem::web::Data;
use poem::{Endpoint, FromRequest, IntoResponse, Middleware, Request, Response};
use warpgate_common_http::auth::UnauthenticatedRequestContext;

use crate::common::{SESSION_COOKIE_NAME, host_is_subdomain_of_or_equal, is_localhost_host};

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

fn normalize_cookie_domain(base_domain: &str) -> String {
    if base_domain.starts_with('.') {
        base_domain.to_string()
    } else {
        format!(".{base_domain}")
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

#[derive(Debug, PartialEq, Eq)]
enum DomainChange {
    /// Set common parent domain
    Set(String),
    Unset,
    Keep,
}

fn decide_domain_change(host: Option<&str>, base_domain: Option<&str>) -> DomainChange {
    match (host, base_domain) {
        // - No Host header and a base domain is configured -> use base domain
        (None, Some(base)) => DomainChange::Set(normalize_cookie_domain(base)),

        // - localhost → remove domain
        (Some(h), _) if is_localhost_host(h) => DomainChange::Unset,

        // - Host == external_host exactly or Host is a subdomain -> set Domain to base_domain
        (Some(h), Some(base)) if host_is_subdomain_of_or_equal(h, base) => {
            DomainChange::Set(normalize_cookie_domain(base))
        }
        _ => DomainChange::Keep,
    }
}

fn rewrite_session_cookie(cookie: &mut Cookie<'_>, action: &DomainChange, is_https: bool) {
    match action {
        DomainChange::Set(domain) => cookie.set_domain(domain.clone()),
        DomainChange::Unset => cookie.unset_domain(),
        DomainChange::Keep => {}
    }
    if is_https {
        cookie.set_secure(true);
        if *action != DomainChange::Keep {
            // disable SameSite when cookie is shared between domains
            cookie.set_same_site(cookie::SameSite::None);
        }
    }
}

impl<E: Endpoint> Endpoint for CookieHostMiddlewareEndpoint<E> {
    type Output = Response;

    async fn call(&self, req: Request) -> poem::Result<Self::Output> {
        let ctx = Data::<&UnauthenticatedRequestContext>::from_request_without_body(&req).await?;
        let host = ctx.trusted_hostname(&req);
        let is_https = ctx.trusted_proto(&req) == Scheme::HTTPS;

        let mut resp = self.inner.call(req).await?.into_response();

        let action = decide_domain_change(host.as_deref(), self.base_domain.as_deref());
        if action == DomainChange::Keep && !is_https {
            return Ok(resp);
        }

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
                rewrite_session_cookie(&mut cookie, &action, is_https);
                modified_session_cookie = Some(cookie.to_string());
                tracing::debug!(
                    "CookieHostMiddleware: Modified cookie - action={:?}, is_https={}",
                    action,
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
                if let Ok(cookie) = Cookie::parse(cookie_str)
                    && cookie.name() != SESSION_COOKIE_NAME
                    && let Ok(header_value) = cookie_str.parse::<http::HeaderValue>()
                {
                    headers.append(http::header::SET_COOKIE, header_value);
                }
            }
        }

        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewritten(host: Option<&str>, base: Option<&str>, is_https: bool) -> Cookie<'static> {
        let mut cookie = Cookie::new(SESSION_COOKIE_NAME, "v");
        rewrite_session_cookie(&mut cookie, &decide_domain_change(host, base), is_https);
        cookie
    }

    #[test]
    fn https_cookie_is_always_secure() {
        for (host, base) in [
            (Some("app.example.com"), Some("example.com")),
            (Some("other.net"), Some("example.com")),
            (Some("other.net"), None),
            (Some("localhost"), None),
            (None, None),
        ] {
            assert_eq!(
                rewritten(host, base, true).secure(),
                Some(true),
                "{host:?} {base:?}"
            );
        }
    }

    #[test]
    fn plain_http_cookie_is_never_secure() {
        for (host, base) in [
            (Some("app.example.com"), Some("example.com")),
            (Some("other.net"), Some("example.com")),
            (Some("localhost"), None),
        ] {
            assert_eq!(
                rewritten(host, base, false).secure(),
                None,
                "{host:?} {base:?}"
            );
        }
    }

    #[test]
    fn host_scoped_cookie_keeps_default_same_site() {
        let c = rewritten(Some("other.net"), Some("example.com"), true);
        assert_eq!(c.domain(), None);
        assert_eq!(c.same_site(), None);
    }

    #[test]
    fn shared_domain_cookie_is_cross_site() {
        let c = rewritten(Some("app.example.com"), Some("example.com"), true);
        assert_eq!(c.domain(), Some("example.com"));
        assert_eq!(c.same_site(), Some(cookie::SameSite::None));
    }

    #[test]
    fn localhost_drops_domain() {
        let mut c = Cookie::new(SESSION_COOKIE_NAME, "v");
        c.set_domain(".example.com");
        rewrite_session_cookie(
            &mut c,
            &decide_domain_change(Some("127.0.0.1"), Some("example.com")),
            true,
        );
        assert_eq!(c.domain(), None);
    }
}
