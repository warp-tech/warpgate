use std::error::Error;

use poem::error::ResponseError;
use uuid::Uuid;

#[derive(thiserror::Error, Debug)]
pub enum WarpgateError {
    #[error("database error: {0}")]
    DatabaseError(#[from] sea_orm::DbErr),
    #[error("ticket not found: {0}")]
    InvalidTicket(Uuid),
    #[error("invalid credential type")]
    InvalidCredentialType,
    #[error(transparent)]
    Other(Box<dyn Error + Send + Sync>),
    #[error("user {0} not found")]
    UserNotFound(String),
    #[error("role {0} not found")]
    RoleNotFound(String),
    #[error("failed to parse URL: {0}")]
    UrlParse(#[from] url::ParseError),
    #[error("deserialization failed: {0}")]
    DeserializeJson(#[from] serde_json::Error),
    #[error("no valid Host header found and `external_host` config option is not set")]
    ExternalHostUnknown,
    #[error("current hostname ({0}) is not on the whitelist ({1:?})")]
    ExternalHostNotWhitelisted(String, Vec<String>),
    #[error("URL contains no host")]
    NoHostInUrl,
    #[error("Inconsistent state error")]
    InconsistentState,
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),

    #[error("Session end")]
    SessionEnd,
}

impl ResponseError for WarpgateError {
    fn status(&self) -> poem::http::StatusCode {
        poem::http::StatusCode::INTERNAL_SERVER_ERROR
    }
}

impl WarpgateError {
    pub fn other<E: Error + Send + Sync + 'static>(err: E) -> Self {
        Self::Other(Box::new(err))
    }
}
