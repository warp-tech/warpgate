use std::error::Error;

use poem::error::ResponseError;
use poem_openapi::ApiResponse;
use uuid::Uuid;
use warpgate_ca::CaError;
use warpgate_sso::SsoError;

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
    #[error(transparent)]
    Sso(#[from] SsoError),
    #[error(transparent)]
    Ca(#[from] CaError),
    #[error(transparent)]
    Ldap(#[from] warpgate_ldap::LdapError),
    #[error(transparent)]
    RusshKeys(#[from] russh::keys::Error),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    RateLimiterInsufficientCapacity(#[from] governor::InsufficientCapacity),
    #[error("Invalid rate limiter quota: {0}")]
    RateLimiterInvalidQuota(u32),
    #[error("Session end")]
    SessionEnd,
    #[error("rcgen: {0}")]
    RcGen(#[from] rcgen::Error),
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

impl ApiResponse for WarpgateError {
    fn meta() -> poem_openapi::registry::MetaResponses {
        poem::error::Error::meta()
    }

    fn register(registry: &mut poem_openapi::registry::Registry) {
        poem::error::Error::register(registry)
    }
}
