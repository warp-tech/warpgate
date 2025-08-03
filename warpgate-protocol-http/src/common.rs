use core::str;
use std::sync::Arc;

use anyhow::Context;
use http::{HeaderName, StatusCode};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use poem::session::Session;
use poem::web::{Data, Redirect};
use poem::{Endpoint, EndpointExt, FromRequest, IntoResponse, Request, Response};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_common::auth::{AuthState, AuthStateUserInfo, CredentialKind};
use warpgate_common::{ProtocolName, TargetOptions, WarpgateError};
use warpgate_core::{AuthStateStore, ConfigProvider, Services};
use warpgate_sso::CoreIdToken;

use crate::session::SessionStore;

pub const PROTOCOL_NAME: ProtocolName = "HTTP";
static TARGET_SESSION_KEY: &str = "target_name";
static AUTH_SESSION_KEY: &str = "auth";
static AUTH_STATE_ID_SESSION_KEY: &str = "auth_state_id";
static AUTH_SSO_LOGIN_STATE: &str = "auth_sso_login_state";
pub static SESSION_COOKIE_NAME: &str = "warpgate-http-session";
static X_WARPGATE_TOKEN: HeaderName = HeaderName::from_static("x-warpgate-token");

#[derive(Serialize, Deserialize)]
pub struct SsoLoginState {
    pub token: CoreIdToken,
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
        self.remove(AUTH_STATE_ID_SESSION_KEY)
    }

    fn get_sso_login_state(&self) -> Option<SsoLoginState> {
        self.get::<String>(AUTH_SSO_LOGIN_STATE)
            .and_then(|x| serde_json::from_str(&x).ok())
    }

    fn set_sso_login_state(&self, state: SsoLoginState) {
        if let Ok(json) = serde_json::to_string(&state) {
            self.set(AUTH_SSO_LOGIN_STATE, json)
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthStateId(pub Uuid);

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum SessionAuthorization {
    User(String),
    Ticket {
        username: String,
        target_name: String,
    },
}

impl SessionAuthorization {
    pub fn username(&self) -> &String {
        match self {
            Self::User(username) => username,
            Self::Ticket { username, .. } => username,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum RequestAuthorization {
    Session(SessionAuthorization),
    UserToken { username: String },
    AdminToken,
}

impl RequestAuthorization {
    pub fn username(&self) -> Option<&String> {
        match self {
            Self::Session(auth) => Some(auth.username()),
            Self::UserToken { username } => Some(username),
            Self::AdminToken => None,
        }
    }
}

pub async fn is_user_admin(req: &Request, auth: &RequestAuthorization) -> poem::Result<bool> {
    let services = Data::<&Services>::from_request_without_body(req).await?;

    let username = match auth {
        RequestAuthorization::Session(SessionAuthorization::User(username)) => username,
        RequestAuthorization::Session(SessionAuthorization::Ticket { .. }) => return Ok(false),
        RequestAuthorization::UserToken { username } => username,
        RequestAuthorization::AdminToken => return Ok(true),
    };

    let mut config_provider = services.config_provider.lock().await;
    let targets = config_provider.list_targets().await?;
    for target in targets {
        if matches!(target.options, TargetOptions::WebAdmin(_))
            && config_provider
                .authorize_target(username, &target.name)
                .await?
        {
            drop(config_provider);
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn endpoint_admin_auth<E: Endpoint + 'static>(e: E) -> impl Endpoint {
    e.around(|ep, req| async move {
        let auth = Data::<&RequestAuthorization>::from_request_without_body(&req).await?;
        if is_user_admin(&req, &auth).await? {
            return Ok(ep.call(req).await?.into_response());
        }
        Err(poem::Error::from_status(StatusCode::UNAUTHORIZED))
    })
}

pub fn page_admin_auth<E: Endpoint + 'static>(e: E) -> impl Endpoint {
    e.around(|ep, req| async move {
        let auth = Data::<&RequestAuthorization>::from_request_without_body(&req).await?;
        let session = <&Session>::from_request_without_body(&req).await?;
        if is_user_admin(&req, &auth).await? {
            return Ok(ep.call(req).await?.into_response());
        }
        session.clear();
        Ok(gateway_redirect(&req).into_response())
    })
}

pub(crate) async fn inject_request_authorization<E: Endpoint + 'static>(
    ep: Arc<E>,
    req: Request,
) -> poem::Result<E::Output> {
    let session = <&Session>::from_request_without_body(&req).await?;
    let services = Data::<&Services>::from_request_without_body(&req).await?;

    let auth = match session.get_auth() {
        Some(auth) => Some(RequestAuthorization::Session(auth)),
        None => match req.headers().get(&X_WARPGATE_TOKEN) {
            Some(token_from_header) => {
                let token_from_header = token_from_header
                    .to_str()
                    .map_err(poem::error::BadRequest)?;
                if Some(token_from_header) == services.admin_token.lock().await.as_deref() {
                    Some(RequestAuthorization::AdminToken)
                } else if let Some(user) = services
                    .config_provider
                    .lock()
                    .await
                    .validate_api_token(token_from_header)
                    .await?
                {
                    Some(RequestAuthorization::UserToken {
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
        // data_opt would change the return type from E::Output
        Ok(ep.data(auth).call(req).await?)
    } else {
        Ok(ep.call(req).await?)
    }
}

pub async fn _inner_auth<E: Endpoint + 'static>(
    ep: Arc<E>,
    req: Request,
) -> poem::Result<Option<E::Output>> {
    let auth = Option::<Data<&RequestAuthorization>>::from_request_without_body(&req).await?;
    if auth.is_none() {
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
            .map(IntoResponse::into_response)
            .unwrap_or(err_resp))
    })
}

pub fn gateway_redirect(req: &Request) -> Response {
    let path = req
        .original_uri()
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| "".into());

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
) -> Result<Arc<Mutex<AuthState>>, WarpgateError> {
    if let Some(id) = session.get_auth_state_id() {
        if !store.contains_key(&id.0) {
            session.remove(AUTH_STATE_ID_SESSION_KEY)
        }
    }

    if let Some(id) = session.get_auth_state_id() {
        let state = store.get(&id.0).ok_or(WarpgateError::InconsistentState)?;

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
        )
        .await?;
    session.set(AUTH_STATE_ID_SESSION_KEY, AuthStateId(id));
    Ok(state)
}

pub async fn authorize_session(
    req: &Request,
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
        .create_handle_for(req)
        .await
        .context("create_handle_for")?;
    server_handle
        .lock()
        .await
        .set_user_info(user_info.clone())
        .await?;
    session.set_auth(SessionAuthorization::User(user_info.username));

    Ok(())
}
