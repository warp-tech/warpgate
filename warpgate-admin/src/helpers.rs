use poem::{Endpoint, FromRequest, EndpointExt};
use poem::http::StatusCode;
use poem::session::Session;

pub type ApiResult<T> = poem::Result<T>;

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

        if !session.is_authenticated() {
            return Err(poem::Error::from_string(
                "Unauthorized",
                StatusCode::UNAUTHORIZED,
            ));
        }
        ep.call(req).await
    })
}
