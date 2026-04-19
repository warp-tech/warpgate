use std::error::Error;

use poem::error::ResponseError;
use poem_openapi::ApiResponse;
use uuid::Uuid;
use warpgate_aws::AwsError;
use warpgate_ca::CaError;
use warpgate_sso::SsoError;
use warpgate_tls::RustlsSetupError;

use crate::AdminPermission;

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
    #[error("Inconsistent state: {0}")]
    InconsistentState(String),
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
    #[error("rustls setup: {0}")]
    TlsSetup(#[from] RustlsSetupError),
    #[error("reqwest: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("admin role required")]
    NoAdminAccess,
    #[error("admin permission required: {0:?}")]
    NoAdminPermission(AdminPermission),
    #[error("AWS: {0}")]
    Aws(AwsError),
    #[error("IP address {0} is not in the allowed range for user {1}")]
    IpAddrNotAllowed(String, String),
    #[error("could not parse IP network address: {0}")]
    InvalidNetworkAddress(String),
}

impl ResponseError for WarpgateError {
    fn status(&self) -> poem::http::StatusCode {
        match self {
            Self::InvalidTicket(_)
            | Self::UserNotFound(_)
            | Self::RoleNotFound(_)
            | Self::IpAddrNotAllowed(..) => poem::http::StatusCode::UNAUTHORIZED,
            Self::NoAdminAccess | Self::NoAdminPermission(_) => poem::http::StatusCode::FORBIDDEN,
            _ => poem::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<Box<dyn Error + Send + Sync + 'static>> for WarpgateError {
    fn from(err: Box<dyn Error + Send + Sync + 'static>) -> Self {
        Self::Other(err)
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
        poem::error::Error::register(registry);
    }
}
