use std::sync::Arc;
use std::time::Duration;

use http::StatusCode;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use poem::session::Session;
use poem::web::{Data, Redirect};
use poem::{Endpoint, EndpointExt, FromRequest, IntoResponse, Request, Response};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::*;
use uuid::Uuid;
use warpgate_common::auth::AuthState;
use warpgate_common::{ProtocolName, TargetOptions, WarpgateError};
use warpgate_core::{AuthStateStore, Services};

use crate::session::SessionStore;

pub const PROTOCOL_NAME: ProtocolName = "HTTP";
static TARGET_SESSION_KEY: &str = "target_name";
static AUTH_SESSION_KEY: &str = "auth";
static AUTH_STATE_ID_SESSION_KEY: &str = "auth_state_id";
pub static SESSION_MAX_AGE: Duration = Duration::from_secs(60 * 30);
pub static COOKIE_MAX_AGE: Duration = Duration::from_secs(60 * 60 * 24);
pub static SESSION_COOKIE_NAME: &str = "warpgate-http-session";

pub trait SessionExt {
    fn has_selected_target(&self) -> bool;
    fn get_target_name(&self) -> Option<String>;
    fn set_target_name(&self, target_name: String);
    fn is_authenticated(&self) -> bool;
    fn get_username(&self) -> Option<String>;
    fn get_auth(&self) -> Option<SessionAuthorization>;
    fn set_auth(&self, auth: SessionAuthorization);
    fn get_auth_state_id(&self) -> Option<AuthStateId>;
}

impl SessionExt for Session {
    fn has_selected_target(&self) -> bool {
        self.get_target_name().is_some()
    }

    fn get_target_name(&self) -> Option<String> {
        self.get(TARGET_SESSION_KEY)
    }

    fn set_target_name(&self, target_name: String) {
        self.set(TARGET_SESSION_KEY, target_name);
    }

    fn is_authenticated(&self) -> bool {
        self.get_username().is_some()
    }

    fn get_username(&self) -> Option<String> {
        return self.get_auth().map(|x| x.username().to_owned());
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
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthStateId(pub Uuid);

#[derive(Clone, Serialize, Deserialize)]
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
            SessionAuthorization::User(username) => username,
            SessionAuthorization::Ticket { username, .. } => username,
        }
    }
}

async fn is_user_admin(req: &Request, auth: &SessionAuthorization) -> poem::Result<bool> {
    let services: Data<&Services> = <_>::from_request_without_body(&req).await?;

    let SessionAuthorization::User(username) = auth else {
        return Ok(false)
    };

    let mut config_provider = services.config_provider.lock().await;
    let targets = config_provider.list_targets().await?;
    for target in targets {
        if matches!(target.options, TargetOptions::WebAdmin(_))
            && config_provider
                .authorize_target(&username, &target.name)
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
        let auth: Data<&SessionAuthorization> = <_>::from_request_without_body(&req).await?;
        if is_user_admin(&req, &auth).await? {
            return Ok(ep.call(req).await?.into_response());
        }
        Err(poem::Error::from_status(StatusCode::UNAUTHORIZED))
    })
}

pub fn page_admin_auth<E: Endpoint + 'static>(e: E) -> impl Endpoint {
    e.around(|ep, req| async move {
        let auth: Data<&SessionAuthorization> = <_>::from_request_without_body(&req).await?;
        let session: &Session = <_>::from_request_without_body(&req).await?;
        if is_user_admin(&req, &auth).await? {
            return Ok(ep.call(req).await?.into_response());
        }
        session.clear();
        Ok(gateway_redirect(&req).into_response())
    })
}

pub async fn _inner_auth<E: Endpoint + 'static>(
    ep: Arc<E>,
    req: Request,
) -> poem::Result<Option<E::Output>> {
    let session: &Session = FromRequest::from_request_without_body(&req).await?;

    Ok(match session.get_auth() {
        Some(auth) => Some(ep.data(auth).call(req).await?),
        _ => None,
    })
}

pub fn endpoint_auth<E: Endpoint + 'static>(e: E) -> impl Endpoint {
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
        .unwrap_or("".into());

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
    match session.get_auth_state_id() {
        Some(id) => {
            if !store.contains_key(&id.0) {
                session.remove(AUTH_STATE_ID_SESSION_KEY)
            }
        }
        None => (),
    };

    match session.get_auth_state_id() {
        Some(id) => Ok(store.get(&id.0).unwrap()),
        None => {
            let (id, state) = store
                .create(&username, crate::common::PROTOCOL_NAME)
                .await?;
            session.set(AUTH_STATE_ID_SESSION_KEY, AuthStateId(id));
            Ok(state)
        }
    }
}

pub async fn authorize_session(req: &Request, username: String) -> poem::Result<()> {
    let session_middleware: Data<&Arc<Mutex<SessionStore>>> =
        <_>::from_request_without_body(&req).await?;
    let session: &Session = <_>::from_request_without_body(&req).await?;

    let server_handle = session_middleware
        .lock()
        .await
        .create_handle_for(&req)
        .await?;
    server_handle
        .lock()
        .await
        .set_username(username.clone())
        .await?;
    info!(%username, "Authenticated");
    session.set_auth(SessionAuthorization::User(username));

    Ok(())
}
