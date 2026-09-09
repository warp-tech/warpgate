use std::error::Error;

use poem::error::ResponseError;
use poem_openapi::ApiResponse;
use uuid::Uuid;
use warpgate_aws::AwsError;
use warpgate_ca::CaError;
use warpgate_ldap::LdapError;
use warpgate_sso::SsoError;
use warpgate_tls::RustlsSetupError;

use crate::AdminPermission;

#[derive(thiserror::Error, Debug)]
pub enum WarpgateError {
    #[error("database error: {0}")]
    DatabaseError(#[from] sea_orm::DbErr),
    #[error("ticket not found: {0}")]
    InvalidTicket(Uuid),
    #[error("invalid target")]
    InvalidTarget,
    #[error("invalid credential type")]
    InvalidCredentialType,
    #[error(transparent)]
    Other(Box<dyn Error + Send + Sync>),
    #[error("user {0} not found")]
    UserNotFound(String),
    #[error("user {0} already exists")]
    UserAlreadyExists(String),
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
    #[error("target session requires administrator approval")]
    TargetSessionRequiresApproval,
    /// Somebody called WarpgateServerHandle::set_user_info twice
    #[error("user session is already attributed to another user")]
    UserSessionAlreadyAttributed,
    #[error("user session is no longer open")]
    UserSessionEnded,
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
    #[error(transparent)]
    Sso(#[from] SsoError),
    #[error(transparent)]
    Ca(#[from] CaError),
    #[error(transparent)]
    Ldap(#[from] LdapError),
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
    #[error("session limit reached")]
    SessionLimitReached,
    #[error(transparent)]
    Encryption(#[from] crate::encryption::EncryptionError),
}

/// An alternative to the poem's ResponseError that provides a simplified error reason for the client without sensitive info
pub trait UserFacingReason {
    fn user_facing_reason(&self) -> String;
}

impl UserFacingReason for WarpgateError {
    fn user_facing_reason(&self) -> String {
        match self {
            Self::InvalidTicket(_)
            | Self::InvalidTarget
            | Self::InvalidCredentialType
            | Self::UserNotFound(_)
            | Self::UserAlreadyExists(_)
            | Self::TargetSessionRequiresApproval
            | Self::UserSessionAlreadyAttributed
            | Self::UserSessionEnded
            | Self::NoAdminAccess
            | Self::NoAdminPermission(_)
            | Self::IpAddrNotAllowed(..)
            | Self::InvalidNetworkAddress(_)
            | Self::SessionLimitReached
            | Self::RateLimiterInvalidQuota(_)
            | Self::ExternalHostUnknown
            | Self::NoHostInUrl
            | Self::SessionEnd => self.to_string(),

            Self::Sso(e) => e.user_facing_reason(),
            Self::Ldap(e) => e.user_facing_reason(),

            // Wraps an error this crate does not control, or names a
            // server-side detail. `ExternalHostNotWhitelisted` and
            // `RoleNotFound` read as caller-authored but interpolate the
            // administrator's configuration: a domain whitelist to an
            // anonymous caller, a configured role name to any SSO user.
            Self::DatabaseError(_) => "database error".into(),
            Self::UrlParse(_) => "failed to parse URL".into(),
            Self::DeserializeJson(_) => "deserialization failed".into(),
            Self::InconsistentState(_) => "inconsistent state".into(),
            Self::ExternalHostNotWhitelisted(..) => "hostname is not on the whitelist".into(),
            Self::RoleNotFound(_) => "role not found".into(),
            Self::Io(_) => "I/O error".into(),
            Self::RateLimiterInsufficientCapacity(_) => "rate limiter capacity exceeded".into(),
            Self::RcGen(_) => "certificate generation failed".into(),
            Self::TlsSetup(_) => "TLS setup failed".into(),
            Self::Reqwest(_) => "outbound HTTP request failed".into(),
            Self::Aws(_) => "AWS error".into(),
            Self::Ca(_) => "certificate authority error".into(),
            Self::RusshKeys(_) => "SSH key error".into(),
            Self::Encryption(_) => "credential encryption error".into(),
            Self::Other(_) | Self::Anyhow(_) => self
                .status()
                .canonical_reason()
                .unwrap_or("Error")
                .to_owned(),
        }
    }
}

impl UserFacingReason for SsoError {
    fn user_facing_reason(&self) -> String {
        match self {
            Self::NotOidc | Self::Mitm | Self::LogoutNotSupported => self.to_string(),
            Self::UrlParse(_)
            | Self::ConfigError(_)
            | Self::Configuration(_)
            | Self::UnsupportedEndpointScheme { .. } => "SSO provider configuration error".into(),
            Self::Discovery(_) => "provider discovery error".into(),
            Self::Verification(_)
            | Self::ClaimsVerification(_)
            | Self::Signing(_)
            | Self::Jwt(_)
            | Self::SignatureVerification(_) => "SSO token verification failed".into(),
            Self::Reqwest(_) | Self::Io(_) => "SSO provider request failed".into(),
            Self::GoogleDirectory(_) => "Google Directory API error".into(),
            Self::Other(_) => "SSO error".into(),
        }
    }
}

impl UserFacingReason for LdapError {
    fn user_facing_reason(&self) -> String {
        match self {
            Self::ConnectionFailed(_) => "LDAP connection failed",
            Self::AuthenticationFailed(_) => "LDAP authentication failed",
            Self::QueryFailed(_) => "LDAP query failed",
            Self::TlsError(_) | Self::RustlSetup(_) => "LDAP TLS error",
            Self::InvalidConfiguration(_) => "LDAP configuration is invalid",
            Self::NoUsername(_) => "cannot determine username for user",
            Self::NoUUID(_) => "cannot determine UUID for user",
            Self::AmbiguousMatch { .. } => "LDAP lookup matched more than one entry",
            Self::LdapClientError(_) | Self::JsonError(_) | Self::Other(_) => "LDAP error",
        }
        .into()
    }
}

impl ResponseError for WarpgateError {
    fn status(&self) -> poem::http::StatusCode {
        match self {
            Self::InvalidTicket(_)
            | Self::UserNotFound(_)
            | Self::RoleNotFound(_)
            | Self::IpAddrNotAllowed(..) => poem::http::StatusCode::UNAUTHORIZED,
            Self::UserAlreadyExists(_) => poem::http::StatusCode::CONFLICT,
            Self::NoAdminAccess | Self::NoAdminPermission(_) => poem::http::StatusCode::FORBIDDEN,
            Self::SessionLimitReached => poem::http::StatusCode::TOO_MANY_REQUESTS,
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

#[cfg(test)]
mod tests {
    use super::{UserFacingReason, WarpgateError};

    const LEAK: &str = "database error: SELECT secret FROM credentials";

    /// The variant this exists for: `#[error(transparent)]` around an error
    /// this crate does not control, whose `Display` was never written with an
    /// HTTP client as its audience.
    #[test]
    fn a_wrapped_foreign_error_never_reaches_the_client() {
        let leaky = WarpgateError::Other(LEAK.into());
        // Asserted first, or this test would keep passing if the fixture ever
        // stopped carrying the text and would prove nothing about the boundary.
        assert!(leaky.to_string().contains("SELECT"));
        assert_eq!(leaky.user_facing_reason(), "Internal Server Error");
    }

    /// The other half of the split. Without this the test above would also
    /// pass on a blanket flattening that told every caller nothing at all.
    #[test]
    fn a_message_written_for_the_caller_is_kept() {
        let refusal = WarpgateError::UserNotFound("alice".into());
        assert_eq!(refusal.user_facing_reason(), refusal.to_string());
    }

    /// `ExternalHostNotWhitelisted` reads as caller-authored and is not: its
    /// second field is the admin-configured whitelist, and this fires from the
    /// pre-auth redirect check, so the caller is anonymous.
    #[test]
    fn the_configured_whitelist_is_not_disclosed() {
        let spoofed = WarpgateError::ExternalHostNotWhitelisted(
            "evil.example".into(),
            vec!["internal.corp.example".into()],
        );
        assert!(spoofed.to_string().contains("internal.corp.example"));
        let reason = spoofed.user_facing_reason();
        assert!(!reason.contains("internal.corp.example"), "{reason}");
        assert!(!reason.contains("evil.example"), "{reason}");
    }

    /// A nested error keeps its own kind, and only that.
    #[test]
    fn a_nested_error_passes_its_canonical_reason_through() {
        let sso = WarpgateError::Sso(super::SsoError::Discovery(
            "https://idp.corp.example/.well-known: connection refused".into(),
        ));
        assert_eq!(sso.user_facing_reason(), "provider discovery error");

        let ldap = WarpgateError::Ldap(super::LdapError::AuthenticationFailed(
            "invalid credentials for cn=svc,dc=corp".into(),
        ));
        assert_eq!(ldap.user_facing_reason(), "LDAP authentication failed");
    }
}
