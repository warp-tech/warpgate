use poem_openapi::auth::ApiKey;
use poem_openapi::SecurityScheme;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(SecurityScheme)]
#[oai(ty = "api_key", key_name = "X-Warpgate-Token", key_in = "header")]
#[allow(dead_code)]
pub struct TokenSecurityScheme(ApiKey);

#[derive(SecurityScheme)]
#[oai(ty = "api_key", key_name = "warpgate-http-session", key_in = "cookie")]
#[allow(dead_code)]
pub struct CookieSecurityScheme(ApiKey);

#[derive(SecurityScheme)]
#[allow(dead_code)]
pub enum AnySecurityScheme {
    Token(TokenSecurityScheme),
    Cookie(CookieSecurityScheme),
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
