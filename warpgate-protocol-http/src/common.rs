use core::str;
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::Context;
use http::{HeaderName, StatusCode};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use poem::error::InternalServerError;
use poem::session::Session;
use poem::web::{Data, Redirect};
use poem::{Endpoint, EndpointExt, FromRequest, IntoResponse, Request, Response};
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_common::auth::{AuthState, AuthStateUserInfo, CredentialKind};
use warpgate_common::{ProtocolName, WarpgateError};
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::{
    AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization,
};
use warpgate_core::{AuthStateStore, ConfigProvider};
use warpgate_db_entities::{User, UserAdminRoleAssignment};
use warpgate_sso::WarpgateIdToken;

use crate::session::SessionStore;

pub const PROTOCOL_NAME: ProtocolName = "HTTP";
static TARGET_SESSION_KEY: &str = "target_name";
static AUTH_SESSION_KEY: &str = "auth";
static AUTH_STATE_ID_SESSION_KEY: &str = "auth_state_id";
static AUTH_SSO_LOGIN_STATE: &str = "auth_sso_login_state";
pub static SESSION_COOKIE_NAME: &str = "warpgate-http-session";
pub static X_WARPGATE_TOKEN: HeaderName = HeaderName::from_static("x-warpgate-token");

/// Check if a host is localhost or 127.x.x.x (for development/testing scenarios)
pub fn is_localhost_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host.starts_with("127.")
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
    fn get_username(&self) -> Option<String>;
    fn get_auth(&self) -> Option<SessionAuthorization>;
    fn set_auth(&self, auth: SessionAuthorization);
    fn get_auth_state_id(&self) -> Option<AuthStateId>;
    fn clear_auth_state(&self);

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

    fn get_username(&self) -> Option<String> {
        self.get_auth().map(|x| x.username().to_owned())
    }

    fn get_auth(&self) -> Option<SessionAuthorization> {
        self.get(AUTH_SESSION_KEY)
    }

    fn set_auth(&self, auth: SessionAuthorization) {
        self.set(AUTH_SESSION_KEY, auth);
    }

    fn get_auth_state_id(&self) -> Option<AuthStateId> {
        self.get(AUTH_STATE_ID_SESSION_KEY)
    }

    fn clear_auth_state(&self) {
        self.remove(AUTH_STATE_ID_SESSION_KEY);
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

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthStateId(pub Uuid);

pub async fn is_user_admin(ctx: &AuthenticatedRequestContext) -> poem::Result<bool> {
    // A user is considered an administrator if they have any admin role assigned.
    let services = ctx.services();

    // Admin tokens bypass the database check and are always full administrators.
    if matches!(ctx.auth, RequestAuthorization::AdminToken) {
        return Ok(true);
    }

    let username = match &ctx.auth {
        RequestAuthorization::Session(SessionAuthorization::User { username, .. })
        | RequestAuthorization::UserToken { username, .. } => username,
        RequestAuthorization::Session(SessionAuthorization::Ticket { .. }) => return Ok(false),
        RequestAuthorization::AdminToken => unreachable!(),
    };

    let db = services.db.lock().await;

    let Some(user_model) = User::Entity::find()
        .filter(User::Column::Username.eq(username))
        .one(&*db)
        .await
        .map_err(InternalServerError)?
    else {
        return Ok(false);
    };

    let count: u64 = UserAdminRoleAssignment::Entity::find()
        .filter(UserAdminRoleAssignment::Column::UserId.eq(user_model.id))
        .count(&*db)
        .await
        .map_err(InternalServerError)?;

    Ok(count > 0)
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

pub async fn get_auth_state_for_request(
    username: &str,
    session: &Session,
    store: &mut AuthStateStore,
    remote_ip: Option<IpAddr>,
) -> Result<Arc<Mutex<AuthState>>, WarpgateError> {
    if let Some(id) = session.get_auth_state_id()
        && !store.contains_key(&id.0)
    {
        session.remove(AUTH_STATE_ID_SESSION_KEY);
    }

    if let Some(id) = session.get_auth_state_id() {
        let state = store.get(&id.0).ok_or(WarpgateError::InconsistentState(
            "unknown auth state id".into(),
        ))?;

        let existing_matched = state.lock().await.user_info().username == username;
        if existing_matched {
            return Ok(state);
        }
    }

    let (id, state) = store
        .create(
            None,
            username,
            crate::common::PROTOCOL_NAME,
            &[
                CredentialKind::Password,
                CredentialKind::Sso,
                CredentialKind::Totp,
            ],
            remote_ip,
        )
        .await?;
    session.set(AUTH_STATE_ID_SESSION_KEY, AuthStateId(id));
    Ok(state)
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

    let server_handle = session_middleware
        .lock()
        .await
        .create_handle_for(req, ctx)
        .await
        .context("create_handle_for")?;
    server_handle
        .lock()
        .await
        .set_user_info(user_info.clone())
        .await?;
    session.set_auth(SessionAuthorization::User {
        user_id: user_info.id,
        username: user_info.username,
    });

    Ok(())
}

pub async fn inject_request_authorization<E: Endpoint + 'static>(
    ep: Arc<E>,
    req: Request,
) -> poem::Result<E::Output> {
    let ctx = Data::<&UnauthenticatedRequestContext>::from_request_without_body(&req).await?;
    let session = <&Session>::from_request_without_body(&req).await?;

    let mut session_auth = session.get_auth();
    if session_auth.is_some() {
        let config = ctx.services().config.lock().await;
        if let Ok(base_url) = config.construct_external_url(None, None)
            && let Some(base_host) = base_url.host_str()
        {
            let request_host = ctx.trusted_hostname(&req);

            if let Some(host) = request_host {
                // Validate request host matches base host or is a subdomain/localhost
                let is_localhost = is_localhost_host(&host);
                let is_authorized = host == base_host
                    || host.ends_with(&format!(".{base_host}"))
                    || (is_localhost && base_host != "localhost" && base_host != "127.0.0.1");

                if !is_authorized {
                    tracing::warn!(
                        "Session cookie rejected: request host '{}' is not authorized (base host: '{}'). Clearing session.",
                        host,
                        base_host
                    );
                    session.clear();
                    session_auth = None;
                }
            }
        }
    }

    let auth = match session_auth {
        Some(auth) => Some(RequestAuthorization::Session(auth)),
        None => match req.headers().get(&X_WARPGATE_TOKEN) {
            Some(token_from_header) => {
                let token_from_header = token_from_header
                    .to_str()
                    .map_err(poem::error::BadRequest)?;
                if ctx
                    .services()
                    .admin_token
                    .lock()
                    .await
                    .as_deref()
                    .is_some_and(|admin_token| {
                        // Use constant time comparison to prevent timing attacks
                        admin_token
                            .as_bytes()
                            .ct_eq(token_from_header.as_bytes())
                            .into()
                    })
                {
                    Some(RequestAuthorization::AdminToken)
                } else if let Some(user) = ctx
                    .services()
                    .config_provider
                    .lock()
                    .await
                    .validate_api_token(token_from_header)
                    .await?
                {
                    Some(RequestAuthorization::UserToken {
                        user_id: user.id,
                        username: user.username,
                    })
                } else {
                    None
                }
            }
            None => None,
        },
    };

    if let Some(auth) = auth {
        // build context and attach it instead of raw authorization
        let ctx = ctx.to_authenticated(auth);
        Ok(ep.data(ctx).call(req).await?)
    } else {
        Ok(ep.call(req).await?)
    }
}
