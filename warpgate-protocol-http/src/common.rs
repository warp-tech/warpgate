use core::str;
use std::sync::Arc;

use anyhow::Context;
use http::{HeaderName, StatusCode};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use poem::error::InternalServerError;
use poem::session::{CookieConfig, Session};
use poem::web::cookie::CookieJar;
use poem::web::{Data, Redirect};
use poem::{Endpoint, EndpointExt, FromRequest, IntoResponse, Request, Response};
use sea_orm::EntityTrait;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_common::auth::{AuthResult, AuthState, AuthStateUserInfo, CredentialKind};
use warpgate_common::helpers::username::username_eq_ci;
use warpgate_common::{Protocol, UserSessionId, WarpgateError};
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::ext::construct_external_url;
use warpgate_common_http::logging::get_client_ip_addr;
use warpgate_common_http::{
    AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization,
    X_WARPGATE_CLUSTER_IDENTITY, is_cluster_peer_request,
};
use warpgate_core::{ConfigProvider, vet_credential_bearer};
use warpgate_db_entities::User;
use warpgate_sso::WarpgateIdToken;

use crate::session::SessionStore;
use crate::session_storage::SharedSessionStorage;

pub const PROTOCOL_NAME: Protocol = Protocol::Http;
static TARGET_SESSION_KEY: &str = "target_name";
static AUTH_SESSION_KEY: &str = "auth";
static AUTH_SSO_LOGIN_STATE: &str = "auth_sso_login_state";
pub static SESSION_COOKIE_NAME: &str = "warpgate-http-session";
pub static X_WARPGATE_TOKEN: HeaderName = HeaderName::from_static("x-warpgate-token");

/// The session cookie's shape — name and (absence of) signing — defined once:
/// the `ServerSession` middleware writes the cookie through this config, and
/// [`storage_session_id`] reads it back through the same one. `max_age` is
/// applied at the middleware wiring, where the write happens.
pub fn session_cookie_config() -> CookieConfig {
    CookieConfig::default()
        .secure(false)
        .name(SESSION_COOKIE_NAME)
}

/// The browser session's storage id from the request's cookie — poem keeps it
/// only there, never inside the session entries.
pub fn storage_session_id(jar: &CookieJar) -> Option<String> {
    session_cookie_config().get_cookie_value(jar)
}

/// Check if a host is localhost or 127.x.x.x (for development/testing scenarios)
pub fn is_localhost_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host.starts_with("127.")
}

pub fn host_is_subdomain_of_or_equal(host: &str, base_domain: &str) -> bool {
    let base = base_domain.trim_start_matches('.');
    host == base || host.ends_with(&format!(".{base}"))
}

/// Whether a request may present a session cookie, given the configured base
/// host: the base host itself, its subdomains, or localhost (for development
/// against a non-localhost deployment). A request whose host cannot be
/// determined proves nothing and is refused — this check must not fail open.
fn session_host_is_authorized(request_host: Option<&str>, base_host: &str) -> bool {
    let Some(host) = request_host else {
        return false;
    };
    host_is_subdomain_of_or_equal(host, base_host)
        || (is_localhost_host(host) && base_host != "localhost" && base_host != "127.0.0.1")
}

#[derive(Serialize, Deserialize)]
pub struct SsoLoginState {
    pub token: WarpgateIdToken,
    pub provider: String,
    pub supports_single_logout: bool,
}

pub trait SessionExt {
    fn get_target_name(&self) -> Option<String>;
    fn set_target_name(&self, target_name: String);
    fn get_auth(&self) -> Option<SessionAuthorization>;
    fn set_auth(&self, auth: SessionAuthorization);
    /// The Warpgate session id of this browser session, once one has been
    /// registered for it. Unlike [`session_id_for_request`] this never creates
    /// one.
    fn get_session_id(&self) -> Option<UserSessionId>;

    fn get_sso_login_state(&self) -> Option<SsoLoginState>;
    fn set_sso_login_state(&self, token: SsoLoginState);
}

impl SessionExt for Session {
    fn get_target_name(&self) -> Option<String> {
        self.get(TARGET_SESSION_KEY)
    }

    fn set_target_name(&self, target_name: String) {
        self.set(TARGET_SESSION_KEY, target_name);
    }

    fn get_auth(&self) -> Option<SessionAuthorization> {
        self.get(AUTH_SESSION_KEY)
    }

    fn set_auth(&self, auth: SessionAuthorization) {
        self.set(AUTH_SESSION_KEY, auth);
    }

    fn get_session_id(&self) -> Option<UserSessionId> {
        self.get(crate::session::SESSION_ID_SESSION_KEY)
    }

    fn get_sso_login_state(&self) -> Option<SsoLoginState> {
        self.get::<String>(AUTH_SSO_LOGIN_STATE)
            .and_then(|x| serde_json::from_str(&x).ok())
    }

    fn set_sso_login_state(&self, state: SsoLoginState) {
        if let Ok(json) = serde_json::to_string(&state) {
            self.set(AUTH_SSO_LOGIN_STATE, json);
        }
    }
}

pub async fn is_user_admin(ctx: &AuthenticatedRequestContext) -> poem::Result<bool> {
    // A user is an administrator if they hold any admin permission. Resolved through the one
    // shared permission loader so this can't drift from the endpoint gate or the /info UI.
    Ok(warpgate_admin::api::admin_permission_set(ctx)
        .await
        .map_err(InternalServerError)?
        .is_admin())
}

pub async fn _inner_auth<E: Endpoint + 'static>(
    ep: Arc<E>,
    req: Request,
) -> poem::Result<Option<E::Output>> {
    let ctx = Option::<Data<&AuthenticatedRequestContext>>::from_request_without_body(&req).await?;
    if ctx.is_none() {
        return Ok(None);
    }
    return ep.call(req).await.map(Some);
}

// TODO unify both based on the accept header
pub fn endpoint_auth<E: Endpoint + 'static>(e: E) -> impl Endpoint<Output = E::Output> {
    e.around(|ep, req| async move {
        _inner_auth(ep, req)
            .await?
            .ok_or_else(|| poem::Error::from_status(StatusCode::UNAUTHORIZED))
    })
}

pub fn page_auth<E: Endpoint + 'static>(e: E) -> impl Endpoint {
    e.around(|ep, req| async move {
        let err_resp = gateway_redirect(&req).into_response();
        Ok(_inner_auth(ep, req)
            .await?
            .map_or(err_resp, IntoResponse::into_response))
    })
}

pub fn gateway_redirect(req: &Request) -> Response {
    // Only do a login redirect for document requests
    if let Some(mode) = req.headers().get(HeaderName::from_static("sec-fetch-mode"))
        && mode != "navigate"
    {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .finish();
    }

    let path = req
        .original_uri()
        .path_and_query()
        .map_or_else(String::new, ToString::to_string);

    let path = format!(
        "/@warpgate#/login?next={}",
        utf8_percent_encode(&path, NON_ALPHANUMERIC),
    );

    Redirect::temporary(path).into_response()
}

pub async fn get_or_create_auth_state_for_request(
    req: &Request,
    username: &str,
    ctx: &UnauthenticatedRequestContext,
    rate_limit_credential_type: Option<&str>,
) -> Result<Arc<Mutex<AuthState>>, WarpgateError> {
    let client_ip = get_client_ip_addr(req, ctx.services()).await;

    if let Some(state) = get_auth_state_for_request(req, ctx).await? {
        let reusable = {
            let state = state.lock().await;
            // A terminally rejected attempt can never accept another
            // credential, so a retry must start a fresh one.
            username_eq_ci(&state.user_info().username, username)
                && !matches!(state.verify(), AuthResult::Rejected)
        };
        if reusable {
            return Ok(state);
        }
    }

    // Pass the browser session id so the auth state is keyed by it: a web
    // approval landing on another node resolves the owner from the session's
    // `node_id` in the DB (see `api::auth::auth_state_owner`).
    let session_id = session_id_for_request(req, ctx).await?;

    let state = ctx
        .services()
        .create_auth_state(
            &session_id,
            username,
            crate::common::PROTOCOL_NAME,
            "",
            &[
                CredentialKind::Password,
                CredentialKind::Sso,
                CredentialKind::Totp,
            ],
            client_ip,
            rate_limit_credential_type,
        )
        .await?;

    Ok(state)
}

/// The login attempt in progress on this browser session, if any. Auth states
/// are keyed by session id, so the session itself is the lookup key and there is
/// nothing to keep in sync.
pub async fn get_auth_state_for_request(
    req: &Request,
    ctx: &UnauthenticatedRequestContext,
) -> Result<Option<Arc<Mutex<AuthState>>>, WarpgateError> {
    let session = <&Session>::from_request_without_body(req)
        .await
        .context("Session not in request")?;

    let Some(session_id) = session.get_session_id() else {
        return Ok(None);
    };

    Ok(ctx
        .services()
        .auth_state_store
        .lock()
        .await
        .get(&session_id))
}

pub async fn session_id_for_request(
    req: &Request,
    ctx: &UnauthenticatedRequestContext,
) -> Result<UserSessionId, WarpgateError> {
    let session_middleware = Data::<&Arc<Mutex<SessionStore>>>::from_request_without_body(req)
        .await
        .context("SessionStore not in request")?;

    let server_handle = session_middleware
        .lock()
        .await
        .handle_for_request(req, ctx)
        .await
        .context("creating session handle")?;

    Ok(server_handle.lock().await.user_session_id())
}

pub async fn authorize_session(
    req: &Request,
    ctx: &UnauthenticatedRequestContext,
    user_info: AuthStateUserInfo,
) -> Result<(), WarpgateError> {
    let session_middleware = Data::<&Arc<Mutex<SessionStore>>>::from_request_without_body(req)
        .await
        .context("SessionStore not in request")?;
    let session = <&Session>::from_request_without_body(req)
        .await
        .context("Session not in request")?;

    let mut server_handle = session_middleware
        .lock()
        .await
        .handle_for_request(req, ctx)
        .await
        .context("resolving session handle")?;

    // session user cannot be switched, so a second attempt should kill
    // thi session and init a new one
    let attributed = server_handle
        .lock()
        .await
        .set_user_info(user_info.clone())
        .await;
    match attributed {
        Ok(()) => {}
        Err(WarpgateError::UserSessionAlreadyAttributed) => {
            let old_id = server_handle.lock().await.user_session_id();
            {
                let mut store = session_middleware.lock().await;
                store.remove_session(session);
            }
            ctx.services()
                .state
                .lock()
                .await
                .remove_session(old_id)
                .await;
            session.clear();
            server_handle = session_middleware
                .lock()
                .await
                .handle_for_request(req, ctx)
                .await
                .context("registering replacement session")?;
            server_handle
                .lock()
                .await
                .set_user_info(user_info.clone())
                .await?;
        }
        Err(error) => return Err(error),
    }

    // when auth is completed, we must rotate the cookie *on the first hop*
    // since cookies set by a forwarded request are not passed back to the client
    if !warpgate_common_http::is_cluster_peer_request(req, &ctx.services().cluster_token) {
        // we are the first hop

        let jar = <&CookieJar>::from_request_without_body(req)
            .await
            .context("CookieJar not in request")?;
        Data::<&SharedSessionStorage>::from_request_without_body(req)
            .await
            .context("SharedSessionStorage not in request")?
            .rotate_session_id(storage_session_id(jar), session)
            .await?;
    }

    session.set_auth(SessionAuthorization::User {
        user_id: user_info.id,
        username: user_info.username,
    });
    warpgate_common_http::auth::stamp_session_auth_time(session);

    Ok(())
}

/// Authorization for a request authenticated by the cluster token. The proxying
/// node forwards the acting user's id in `x-warpgate-cluster-identity` (see
/// `cluster_proxy::proxy_or_serve`), so the request runs here as that user;
/// without the header the peer acts as a bare cluster peer. An id that no
/// longer resolves to a user fails closed (unauthenticated).
async fn cluster_request_authorization(
    ctx: &UnauthenticatedRequestContext,
    req: &Request,
) -> poem::Result<Option<RequestAuthorization>> {
    let Some(header) = req.headers().get(&X_WARPGATE_CLUSTER_IDENTITY) else {
        return Ok(Some(RequestAuthorization::ClusterToken));
    };
    let Some(user_id) = header.to_str().ok().and_then(|s| s.parse::<Uuid>().ok()) else {
        return Ok(None);
    };
    Ok(User::Entity::find_by_id(user_id)
        .one(&ctx.services().db)
        .await
        .map_err(poem::error::InternalServerError)?
        .map(|user| {
            RequestAuthorization::Session(SessionAuthorization::User {
                user_id: user.id,
                username: user.username,
            })
        }))
}

/// Resolves an API token to its user, applying the same account-status checks a
/// login goes through. `None` for an unknown token or for a user who may not
/// authenticate right now — the caller can't tell the two apart, by design.
async fn user_for_api_token(
    req: &Request,
    ctx: &UnauthenticatedRequestContext,
    token: &str,
) -> Result<Option<warpgate_common::User>, WarpgateError> {
    let services = ctx.services();
    let remote_ip = get_client_ip_addr(req, services).await;

    // Checked ahead of the lookup so a blocked caller can't use this as a
    // token-existence oracle.
    if let Some(ip) = remote_ip
        && services
            .login_protection
            .check_ip_blocked(&ip)
            .await?
            .is_some()
    {
        tracing::warn!("API token presented from a blocked IP: {ip}");
        return Ok(None);
    }

    let Some(user) = services.config_provider.validate_api_token(token).await? else {
        return Ok(None);
    };

    if !vet_credential_bearer(&services.login_protection, &user, remote_ip).await? {
        return Ok(None);
    }

    Ok(Some(user))
}

pub async fn inject_request_authorization<E: Endpoint + 'static>(
    ep: Arc<E>,
    req: Request,
) -> poem::Result<E::Output> {
    // Reinject a per-request copy so the parameter cache is request-scoped
    // rather than shared with the startup singleton.
    let ctx = Data::<&UnauthenticatedRequestContext>::from_request_without_body(&req)
        .await?
        .for_request();
    let session = <&Session>::from_request_without_body(&req).await?;
    let is_cluster_peer = is_cluster_peer_request(&req, &ctx.services().cluster_token);

    let mut session_auth = session.get_auth();
    // A forwarded request's Host is the cluster SNI name by construction, so the
    // origin check below would reject - and clear - a session that is fine.
    if session_auth.is_some() && !is_cluster_peer {
        // Host binding only means something when `external_host` pins an
        // origin. Without it the external URL is derived from Host header
        let base_host = {
            let config = ctx.services().config.lock().await;
            construct_external_url(None, &config, None)
                .await
                .ok()
                .and_then(|url| url.host_str().map(str::to_owned))
        };
        if let Some(base_host) = base_host {
            let request_host = ctx.trusted_hostname(&req);
            if !session_host_is_authorized(request_host.as_deref(), &base_host) {
                tracing::warn!(
                    "Session cookie rejected: request host {:?} is not authorized (base host: '{}'). Clearing session.",
                    request_host,
                    base_host
                );
                session.clear();
                session_auth = None;
            }
        }
    }

    let auth = if let Some(auth) = session_auth {
        Some(RequestAuthorization::Session(auth))
    } else if is_cluster_peer {
        cluster_request_authorization(&ctx, &req).await?
    } else if let Some(token_from_header) = req.headers().get(&X_WARPGATE_TOKEN) {
        let token_from_header = token_from_header
            .to_str()
            .map_err(poem::error::BadRequest)?;
        if (*ctx.services().admin_token)
            .as_ref()
            .is_some_and(|admin_token| {
                // Use constant time comparison to prevent timing attacks
                admin_token
                    .expose_secret()
                    .as_bytes()
                    .ct_eq(token_from_header.as_bytes())
                    .into()
            })
        {
            Some(RequestAuthorization::AdminToken)
        } else if let Some(user) = user_for_api_token(&req, &ctx, token_from_header).await? {
            Some(RequestAuthorization::UserToken {
                user_id: user.id,
                username: user.username,
            })
        } else {
            None
        }
    } else {
        None
    };

    if let Some(auth) = auth {
        // build context and attach it instead of raw authorization
        let actx = ctx.to_authenticated(auth);
        Ok(ep.data(actx).data(ctx).call(req).await?)
    } else {
        Ok(ep.data(ctx).call(req).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::{StatusCode, gateway_redirect, host_is_subdomain_of_or_equal};

    #[test]
    fn gateway_redirect_navigation_redirects_to_login() {
        for mode in [None, Some("navigate")] {
            let mut req = poem::Request::builder().uri_str("/api/data");
            if let Some(mode) = mode {
                req = req.header("sec-fetch-mode", mode);
            }
            let resp = gateway_redirect(&req.finish());
            assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
            let location = resp
                .headers()
                .get(http::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            assert!(location.starts_with("/@warpgate#/login"));
        }
    }

    #[test]
    fn gateway_redirect_fetch_gets_401() {
        // https://github.com/warp-tech/warpgate/issues/1989
        for mode in ["cors", "same-origin", "no-cors"] {
            let req = poem::Request::builder()
                .uri_str("/api/data")
                .header("sec-fetch-mode", mode)
                .finish();
            let resp = gateway_redirect(&req);
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[test]
    fn session_host_check_fails_closed() {
        use super::session_host_is_authorized;

        assert!(session_host_is_authorized(
            Some("example.com"),
            "example.com"
        ));
        assert!(session_host_is_authorized(
            Some("app.example.com"),
            "example.com"
        ));
        assert!(session_host_is_authorized(Some("localhost"), "example.com"));
        assert!(!session_host_is_authorized(
            Some("evil-example.com"),
            "example.com"
        ));
        assert!(session_host_is_authorized(Some("localhost"), "localhost"));
        // The localhost exception is for developing against a real deployment,
        // not a blanket pass when the deployment itself is localhost.
        assert!(!session_host_is_authorized(Some("127.0.0.5"), "localhost"));
        // A host that cannot be determined proves nothing.
        assert!(!session_host_is_authorized(None, "example.com"));
    }

    #[test]
    fn test_host_is_subdomain_of_or_equal() {
        assert!(host_is_subdomain_of_or_equal("example.com", "example.com"));
        assert!(host_is_subdomain_of_or_equal(
            "foo.example.com",
            "example.com"
        ));
        assert!(host_is_subdomain_of_or_equal(
            "foo.example.com",
            ".example.com"
        ));
        assert!(!host_is_subdomain_of_or_equal(
            "evil-example.com",
            "example.com"
        ));
    }
}
