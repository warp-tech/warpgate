use poem::error::ResponseError;
use poem::http::header::HeaderValue;
use poem::http::{HeaderName, Method, StatusCode};
use poem::session::Session;
use poem::web::Redirect;
use poem::{IntoResponse, Request, Response};
use thiserror::Error;
use warpgate_common_http::auth::{
    AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization,
};
use warpgate_db_entities::Parameters::MfaEnforcement;

use crate::common::is_navigation_request;

pub static MFA_SETUP_REQUIRED_HEADER: HeaderName =
    HeaderName::from_static("x-warpgate-mfa-setup-required");

const MFA_GATE_PASSED_SESSION_KEY: &str = "mfa_gate_passed";
/// The path relative to the Warpgate app surface, or `None` for proxied
/// target paths.
fn warpgate_surface_path(path: &str) -> Option<&str> {
    path.strip_prefix("/@warpgate")
        .or_else(|| path.strip_prefix("/_warpgate"))
}

/// The URLs a web user held in the MFA enrollment flow may still reach: the
/// SPA shells and their assets (both apps steer held users to the setup route
/// client-side), the enrollment endpoint itself, and enough of the auth API
/// to log in and out. Everything else - including target proxying, the admin
/// API and the web-auth approval endpoints - is blocked.
fn is_mfa_setup_allowed(method: &Method, path: &str) -> bool {
    let Some(path) = warpgate_surface_path(path) else {
        return false;
    };
    if path.is_empty() || path == "/" || path.starts_with("/assets/") {
        return true;
    }
    match path {
        "/admin" | "/api/info" => method == Method::GET,
        "/api/profile/credentials/otp"
        | "/api/auth/login"
        | "/api/auth/otp"
        | "/api/auth/logout" => method == Method::POST,
        // The user's own login state only - the `/api/auth/state/:id/...`
        // approval endpoints stay blocked.
        "/api/auth/state" | "/api/sso/logout" => true,
        _ => false,
    }
}

#[derive(Debug, Error)]
#[error("MFA setup required")]
struct MfaSetupRequiredError {
    should_redirect: bool,
}

impl MfaSetupRequiredError {
    fn for_request(req: &Request) -> Self {
        Self {
            should_redirect: is_navigation_request(req),
        }
    }
}

impl ResponseError for MfaSetupRequiredError {
    fn status(&self) -> StatusCode {
        StatusCode::FORBIDDEN
    }

    fn as_response(&self) -> Response
    where
        Self: std::error::Error + Send + Sync + 'static,
    {
        let mut response = if !self.should_redirect {
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body("MFA setup required")
        } else {
            Redirect::temporary("/@warpgate#/mfa-setup").into_response()
        };
        response.headers_mut().insert(
            MFA_SETUP_REQUIRED_HEADER.clone(),
            HeaderValue::from_static("1"),
        );
        response
    }
}

pub async fn assert_mfa_setup_gate(
    actx: &AuthenticatedRequestContext,
    req: &Request,
    session: &Session,
) -> poem::Result<()> {
    if is_mfa_setup_allowed(req.method(), req.original_uri().path()) {
        return Ok(());
    }

    let RequestAuthorization::Session(SessionAuthorization::User { user_id, .. }) = &actx.auth
    else {
        return Ok(());
    };
    let user_id = *user_id;

    let parameters = actx.parameters().await?;
    if parameters.mfa_enforcement == MfaEnforcement::Off {
        return Ok(());
    }

    if session.get::<bool>(MFA_GATE_PASSED_SESSION_KEY) == Some(true) {
        return Ok(());
    }

    if actx
        .services()
        .mfa_setup_required(parameters, user_id)
        .await?
    {
        return Err(MfaSetupRequiredError::for_request(req).into());
    }

    session.set(MFA_GATE_PASSED_SESSION_KEY, true);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist() {
        for (method, path, allowed) in [
            // SPA shell and assets, on both prefixes
            (Method::GET, "/@warpgate", true),
            (Method::GET, "/@warpgate/", true),
            (Method::GET, "/_warpgate", true),
            (Method::GET, "/@warpgate/assets/index.js", true),
            (Method::GET, "/_warpgate/assets/index.css", true),
            // Enrollment essentials
            (Method::GET, "/@warpgate/api/info", true),
            (Method::POST, "/@warpgate/api/profile/credentials/otp", true),
            (Method::POST, "/_warpgate/api/auth/logout", true),
            (Method::GET, "/@warpgate/api/sso/logout", true),
            (Method::GET, "/@warpgate/api/auth/state", true),
            (Method::DELETE, "/@warpgate/api/auth/state", true),
            (Method::POST, "/@warpgate/api/auth/login", true),
            (Method::POST, "/@warpgate/api/auth/otp", true),
            // Wrong methods
            (Method::POST, "/@warpgate/api/info", false),
            (Method::GET, "/@warpgate/api/profile/credentials/otp", false),
            (
                Method::DELETE,
                "/@warpgate/api/profile/credentials/otp",
                false,
            ),
            // Everything else
            (Method::GET, "/@warpgate/api/targets", false),
            (Method::GET, "/@warpgate/api/profile/credentials", false),
            (
                Method::POST,
                "/@warpgate/api/auth/state/123e4567-e89b-12d3-a456-426614174000/approve",
                false,
            ),
            (Method::GET, "/@warpgate/api/auth/web-auth-requests", false),
            // The admin shell may load (it redirects held users itself);
            // the admin API stays blocked
            (Method::GET, "/@warpgate/admin", true),
            (Method::POST, "/@warpgate/admin", false),
            (Method::GET, "/@warpgate/admin/api/users", false),
            (
                Method::GET,
                "/@warpgate/api/web-ssh/sessions/x/stream",
                false,
            ),
            // Target proxying (catchall)
            (Method::GET, "/", false),
            (Method::GET, "/some/target/path", false),
            (Method::POST, "/warpgate-target=x", false),
        ] {
            assert_eq!(
                is_mfa_setup_allowed(&method, path),
                allowed,
                "{method} {path}"
            );
        }
    }
}
