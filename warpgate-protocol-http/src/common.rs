use std::any::type_name;
use std::sync::Arc;
use std::time::Duration;

use http::StatusCode;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use poem::error::GetDataError;
use poem::session::Session;
use poem::web::{Data, Redirect};
use poem::{Endpoint, EndpointExt, FromRequest, IntoResponse, Request, RequestBody, Response};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, ModelTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::*;
use uuid::Uuid;
use warpgate_common::auth::AuthState;
use warpgate_common::{ProtocolName, TargetOptions, WarpgateError};
use warpgate_core::{AuthStateStore, Services};
use warpgate_db_entities::{Token, User};

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
    fn get_auth(&self) -> Option<SessionAuthorization>;
    fn set_auth(&self, auth: SessionAuthorization);
    fn get_auth_state_id(&self) -> Option<AuthStateId>;
    fn clear_auth_state(&self);
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
            Self::User(username) => username,
            Self::Ticket { username, .. } => username,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum RequestAuthorization {
    Session(SessionAuthorization),
    Token { username: String },
}

impl RequestAuthorization {
    pub fn username(&self) -> &String {
        match self {
            Self::Session(auth) => auth.username(),
            Self::Token { username, .. } => username,
        }
    }
}

#[async_trait::async_trait]
impl<'a> FromRequest<'a> for RequestAuthorization {
    async fn from_request(req: &'a Request, body: &mut RequestBody) -> poem::Result<Self> {
        let session: &Session = <_>::from_request(req, body).await?;
        if let Some(auth) = session.get_auth() {
            return Ok(RequestAuthorization::Session(auth));
        }

        let token = req
            .headers()
            .get("Authorization")
            .and_then(|x| x.to_str().ok())
            .and_then(|x| x.strip_prefix("Bearer "))
            .map(|x| x.to_owned());

        if let Some(token) = token {
            let db: Data<&Arc<Mutex<DatabaseConnection>>> = <_>::from_request(req, body).await?;
            let mut db = db.lock().await;

            let token = utf8_percent_encode(&token, NON_ALPHANUMERIC).to_string();
            let token = Token::Entity::find()
                .filter(Token::Column::Secret.eq(token))
                .one(&mut *db)
                .await
                .map_err(poem::error::InternalServerError)?;
            if let Some(token) = token {
                let user = token
                    .find_related(User::Entity)
                    .one(&mut *db)
                    .await
                    .map_err(poem::error::InternalServerError)?;
                if let Some(user) = user {
                    return Ok(RequestAuthorization::Token {
                        username: user.username,
                    });
                }
            }
        }

        Err(GetDataError(type_name::<RequestAuthorization>()).into())
    }
}

async fn is_user_admin(req: &Request, auth: &RequestAuthorization) -> poem::Result<bool> {
    let services: Data<&Services> = <_>::from_request_without_body(req).await?;

    let username = auth.username();
    if let RequestAuthorization::Session(SessionAuthorization::Ticket { .. }) = auth {
        return Ok(false);
    }

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
        let auth: RequestAuthorization = <_>::from_request_without_body(&req).await?;
        if is_user_admin(&req, &auth).await? {
            return Ok(ep.call(req).await?.into_response());
        }
        Err(poem::Error::from_status(StatusCode::UNAUTHORIZED))
    })
}

pub fn page_admin_auth<E: Endpoint + 'static>(e: E) -> impl Endpoint {
    e.around(|ep, req| async move {
        let auth: RequestAuthorization = <_>::from_request_without_body(&req).await?;
        let session: &Session = <_>::from_request_without_body(&req).await?;
        if is_user_admin(&req, &auth).await? {
            return Ok(ep.call(req).await?.into_response());
        }
        session.clear();
        Ok(gateway_redirect(&req).into_response())
    })
}

pub fn endpoint_auth<E: Endpoint + 'static>(e: E) -> impl Endpoint<Output = E::Output> {
    e.around(|ep, req| async move {
        Option::<RequestAuthorization>::from_request_without_body(&req)
            .await?
            .ok_or_else(|| poem::Error::from_status(StatusCode::UNAUTHORIZED))?;
        ep.call(req).await
    })
}

pub fn page_auth<E: Endpoint + 'static>(e: E) -> impl Endpoint {
    e.around(|ep, req| async move {
        if Option::<RequestAuthorization>::from_request_without_body(&req)
            .await?
            .is_none()
        {
            return Ok(gateway_redirect(&req).into_response());
        }
        Ok(ep.call(req).await?.into_response())
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

    match session.get_auth_state_id() {
        Some(id) => Ok(store.get(&id.0).ok_or(WarpgateError::InconsistentState)?),
        None => {
            let (id, state) = store.create(username, crate::common::PROTOCOL_NAME).await?;
            session.set(AUTH_STATE_ID_SESSION_KEY, AuthStateId(id));
            Ok(state)
        }
    }
}

pub async fn authorize_session(req: &Request, username: String) -> poem::Result<()> {
    let session_middleware: Data<&Arc<Mutex<SessionStore>>> =
        <_>::from_request_without_body(req).await?;
    let session: &Session = <_>::from_request_without_body(req).await?;

    let server_handle = session_middleware
        .lock()
        .await
        .create_handle_for(req)
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
