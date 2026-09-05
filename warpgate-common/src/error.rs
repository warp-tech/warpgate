use std::error::Error;

use poem::error::ResponseError;
use poem::{IntoResponse, Response};
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
    #[error("session limit reached")]
    SessionLimitReached,
    #[error(transparent)]
    Encryption(#[from] crate::encryption::EncryptionError),
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

    // poem's default renders the `Display` of whichever variant fired into
    // the body, which for the `#[error(transparent)]` ones is a foreign
    // error's own words. Exhaustive on purpose: a new variant has to be
    // sorted rather than inherit a catch-all.
    fn as_response(&self) -> Response
    where
        Self: Error + Send + Sync + 'static,
    {
        let message = match self {
            // Written for the caller, interpolating only values they
            // supplied or already know.
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

            // Wraps an error this crate does not control, or names a
            // server-side detail. `ExternalHostNotWhitelisted` and
            // `RoleNotFound` read as caller-authored but interpolate the
            // administrator's configuration: a domain whitelist to an
            // anonymous caller, a configured role name to any SSO user.
            Self::DatabaseError(_)
            | Self::Other(_)
            | Self::UrlParse(_)
            | Self::DeserializeJson(_)
            | Self::InconsistentState(_)
            | Self::ExternalHostNotWhitelisted(..)
            | Self::RoleNotFound(_)
            | Self::Anyhow(_)
            | Self::Sso(_)
            | Self::Ca(_)
            | Self::Ldap(_)
            | Self::RusshKeys(_)
            | Self::Io(_)
            | Self::RateLimiterInsufficientCapacity(_)
            | Self::RcGen(_)
            | Self::TlsSetup(_)
            | Self::Reqwest(_)
            | Self::Aws(_)
            | Self::Encryption(_) => {
                let correlation_id = Uuid::new_v4();
                // `{:#}` renders an `anyhow` chain in full, and this line
                // is the only place that detail goes.
                let detail = format!("{self:#}");
                tracing::error!(
                    correlation_id = %correlation_id,
                    error = %detail,
                    "Request failed with an internal error"
                );
                format!(
                    "{} (reference: {correlation_id})",
                    self.status().canonical_reason().unwrap_or("Error")
                )
            }
        };
        let mut resp = message.into_response();
        resp.set_status(self.status());
        resp
    }
}

/// Renders an error's full text, causal chain included, for an admin-only
/// "test connection" endpoint that exists to answer "what is wrong with this
/// configuration".
///
/// The deliberate opt-out of [`WarpgateError::as_response`]'s flattening.
/// Only for an error the caller asked to see, and never for one that could
/// carry a credential rather than a connection failure.
pub fn client_error_message(err: &(impl std::fmt::Display + ?Sized)) -> String {
    format!("{err:#}")
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
    use poem::error::ResponseError;

    use super::WarpgateError;

    const LEAK: &str = "database error: SELECT secret FROM credentials";

    async fn body_of(response: poem::Response) -> String {
        response.into_body().into_string().await.unwrap()
    }

    /// The variant this override exists for: `#[error(transparent)]` around an
    /// error this crate does not control, whose `Display` was never written
    /// with an HTTP client as its audience.
    #[tokio::test]
    async fn a_wrapped_foreign_error_never_reaches_the_client() {
        let leaky = WarpgateError::Other(LEAK.into());
        // Asserted first, or this test would keep passing if the fixture ever
        // stopped carrying the text and would prove nothing about the boundary.
        assert!(leaky.to_string().contains("SELECT"));

        let body = body_of(leaky.as_response()).await;
        assert!(
            !body.contains("SELECT"),
            "the raw error reached the client: {body}"
        );
        assert!(
            !body.contains("database error"),
            "the raw error reached the client: {body}"
        );
        assert!(
            body.starts_with("Internal Server Error (reference: "),
            "no correlation id to hand an operator: {body}"
        );
    }

    /// The other half of the split. Without this the test above would also
    /// pass on a blanket flattening that told every caller nothing at all.
    #[tokio::test]
    async fn a_message_written_for_the_caller_is_kept() {
        let refusal = WarpgateError::UserNotFound("alice".into());
        let body = body_of(refusal.as_response()).await;
        assert!(
            body.contains("alice"),
            "a deliberate, caller-facing message was flattened away: {body}"
        );
    }

    /// `ExternalHostNotWhitelisted` reads as caller-authored and is not: its
    /// second field is the admin-configured whitelist, and this fires from the
    /// pre-auth redirect check, so the caller is anonymous.
    #[tokio::test]
    async fn the_configured_whitelist_is_not_disclosed() {
        let spoofed = WarpgateError::ExternalHostNotWhitelisted(
            "evil.example".into(),
            vec!["internal.corp.example".into()],
        );
        assert!(spoofed.to_string().contains("internal.corp.example"));

        let body = body_of(spoofed.as_response()).await;
        assert!(
            !body.contains("internal.corp.example"),
            "the whitelist reached an anonymous caller: {body}"
        );
    }

    /// Flattening the body must not flatten the status: the frontends match on
    /// these codes.
    #[tokio::test]
    async fn the_status_code_survives_the_flattening() {
        assert_eq!(
            WarpgateError::Other(LEAK.into()).as_response().status(),
            poem::http::StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            WarpgateError::UserNotFound("alice".into())
                .as_response()
                .status(),
            poem::http::StatusCode::UNAUTHORIZED
        );
    }

    /// The reference is only useful if it identifies one occurrence.
    #[tokio::test]
    async fn each_failure_gets_its_own_reference() {
        let first = body_of(WarpgateError::Other(LEAK.into()).as_response()).await;
        let second = body_of(WarpgateError::Other(LEAK.into()).as_response()).await;
        assert_ne!(first, second, "the correlation id is a constant: {first}");
    }
}
