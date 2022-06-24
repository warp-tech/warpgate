use std::time::Duration;

use http::StatusCode;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use poem::session::Session;
use poem::web::{Data, Redirect};
use poem::{Endpoint, EndpointExt, FromRequest, IntoResponse, Request, Response};
use warpgate_common::{Services, TargetOptions};

static USERNAME_SESSION_KEY: &str = "username";
static TARGET_SESSION_KEY: &str = "target_name";
pub static SESSION_MAX_AGE: Duration = Duration::from_secs(60 * 30);

pub trait SessionExt {
    fn has_selected_target(&self) -> bool;
    fn get_target_name(&self) -> Option<String>;
    fn set_target_name(&self, target_name: String);
    fn is_authenticated(&self) -> bool;
    fn get_username(&self) -> Option<String>;
    fn set_username(&self, username: String);
}

impl SessionExt for Session {
    fn has_selected_target(&self) -> bool {
        self.get_target_name().is_some()
    }

    fn get_target_name(&self) -> Option<String> {
        self.get::<String>(TARGET_SESSION_KEY)
    }

    fn set_target_name(&self, target_name: String) {
        self.set(TARGET_SESSION_KEY, target_name);
    }

    fn is_authenticated(&self) -> bool {
        self.get_username().is_some()
    }

    fn get_username(&self) -> Option<String> {
        self.get::<String>(USERNAME_SESSION_KEY)
    }

    fn set_username(&self, username: String) {
        self.set(USERNAME_SESSION_KEY, username);
    }
}

#[derive(Clone)]
pub struct SessionUsername(pub String);

async fn is_user_admin(req: &Request, username: &SessionUsername) -> poem::Result<bool> {
    let services: Data<&Services> = <_>::from_request_without_body(&req).await?;

    let mut config_provider = services.config_provider.lock().await;
    let targets = config_provider.list_targets().await?;
    for target in targets {
        if matches!(target.options, TargetOptions::WebAdmin(_))
            && config_provider
                .authorize_target(&username.0, &target.name)
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
        let username: Data<&SessionUsername> = <_>::from_request_without_body(&req).await?;
        if is_user_admin(&req, username.0).await? {
            return Ok(ep.call(req).await?.into_response());
        }
        Err(poem::Error::from_status(StatusCode::UNAUTHORIZED))
    })
}

pub fn page_admin_auth<E: Endpoint + 'static>(e: E) -> impl Endpoint {
    e.around(|ep, req| async move {
        let username: Data<&SessionUsername> = <_>::from_request_without_body(&req).await?;
        let session: &Session = <_>::from_request_without_body(&req).await?;
        if is_user_admin(&req, username.0).await? {
            return Ok(ep.call(req).await?.into_response());
        }
        session.clear();
        Ok(gateway_redirect(&req).into_response())
    })
}

pub fn endpoint_auth<E: Endpoint + 'static>(e: E) -> impl Endpoint {
    e.around(|ep, req| async move {
        let session: &Session = FromRequest::from_request_without_body(&req).await?;

        match session.get_username() {
            Some(username) => Ok(ep.data(SessionUsername(username)).call(req).await?),
            None => Err(poem::Error::from_status(StatusCode::UNAUTHORIZED)),
        }
    })
}

pub fn page_auth<E: Endpoint + 'static>(e: E) -> impl Endpoint {
    e.around(|ep, req| async move {
        let session: &Session = FromRequest::from_request_without_body(&req).await?;

        match session.get_username() {
            Some(username) => Ok(ep
                .data(SessionUsername(username))
                .call(req)
                .await?
                .into_response()),
            None => Ok(gateway_redirect(&req).into_response()),
        }
    })
}

pub fn gateway_redirect(req: &Request) -> Response {
    let path = req
        .original_uri()
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or("".into());

    let path = format!(
        "/@warpgate?next={}",
        utf8_percent_encode(&path, NON_ALPHANUMERIC),
    );

    Redirect::temporary(path).into_response()
}
