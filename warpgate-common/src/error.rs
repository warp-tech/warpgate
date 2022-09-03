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
    #[error("user not found")]
    UserNotFound,
    #[error("failed to parse URL: {0}")]
    UrlParse(#[from] url::ParseError),
    #[error("deserialization failed: {0}")]
    DeserializeJson(#[from] serde_json::Error),
    #[error("external_url config option is not set")]
    ExternalHostNotSet,
    #[error("URL contains no host")]
    NoHostInUrl,
    #[error("Inconsistent state error")]
    InconsistentState,

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
