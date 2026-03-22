use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthStateId(pub Uuid);

/// Represents the source of authentication of a session
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

/// Represents the source of authentication in a request
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum RequestAuthorization {
    Session(SessionAuthorization),
    UserToken { username: String },
    AdminToken,
}

#[derive(Clone)]
pub struct UnauthenticatedRequestContext {
    pub services: warpgate_core::Services,
}

/// Provided to API handlers as Data<>
impl UnauthenticatedRequestContext {
    pub fn to_authenticated(&self, auth: RequestAuthorization) -> AuthenticatedRequestContext {
        AuthenticatedRequestContext {
            auth,
            services: self.services.clone(),
        }
    }
}

#[derive(Clone)]
/// Provided to API handlers as Data<> when a request is authenticated
pub struct AuthenticatedRequestContext {
    pub auth: RequestAuthorization,
    pub services: warpgate_core::Services,
}

impl RequestAuthorization {
    /// Returns a username if one is present (admin token has none)
    pub fn username(&self) -> Option<&String> {
        match self {
            Self::Session(auth) => Some(auth.username()),
            Self::UserToken { username } => Some(username),
            Self::AdminToken => None,
        }
    }
}

/// Check if a host is localhost or 127.x.x.x (for development/testing scenarios)
pub fn is_localhost_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host.starts_with("127.")
}
