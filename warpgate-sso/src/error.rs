use std::error::Error;

use openidconnect::{ClaimsVerificationError, SigningError};

#[derive(thiserror::Error, Debug)]
pub enum SsoError {
    #[error("provider is OAuth2, not OIDC")]
    NotOidc,
    #[error("the token was replaced in flight")]
    Mitm,
    #[error("config parse error: {0}")]
    UrlParse(#[from] openidconnect::url::ParseError),
    #[error("config error: {0}")]
    ConfigError(String),
    #[error("provider discovery error: {0}")]
    Discovery(String),
    #[error("code verification error: {0}")]
    Verification(String),
    #[error("claims verification error: {0}")]
    ClaimsVerification(#[from] ClaimsVerificationError),
    #[error("signing error: {0}")]
    Signing(#[from] SigningError),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error(transparent)]
    Other(Box<dyn Error + Send + Sync>),
}
