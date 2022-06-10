use std::sync::Arc;

use poem::http::StatusCode;
use poem::session::Session;
use poem::web::Data;
use poem::{Endpoint, EndpointExt, FromRequest};
use tokio::sync::Mutex;
use warpgate_common::{ConfigProvider, TargetOptions};

static USERNAME_SESSION_KEY: &str = "username";

pub trait SessionExt {
    fn is_authenticated(&self) -> bool;
    fn get_username(&self) -> Option<String>;
    fn set_username(&self, username: String);
}

impl SessionExt for Session {
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

pub fn endpoint_auth<E: Endpoint + 'static>(e: E) -> impl Endpoint {
    e.around(|ep, req| async move {
        let session: &Session = FromRequest::from_request_without_body(&req).await?;
        let config_provider: Data<&Arc<Mutex<dyn ConfigProvider + Send>>> =
            FromRequest::from_request_without_body(&req).await?;

        if let Some(ref username) = session.get_username() {
            let mut config_provider = config_provider.lock().await;
            let targets = config_provider.list_targets().await?;
            for target in targets {
                if matches!(target.options, TargetOptions::WebAdmin(_))
                    && config_provider
                        .authorize_target(username, &target.name)
                        .await?
                {
                    drop(config_provider);
                    return ep.call(req).await;
                }
            }
        }

        Err(poem::Error::from_string(
            "Unauthorized",
            StatusCode::UNAUTHORIZED,
        ))
    })
}
