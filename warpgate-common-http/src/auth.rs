use std::ops::Deref;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use poem::Request;
use poem::http::uri::{Authority, Scheme};
use poem::session::Session;
use serde::{Deserialize, Serialize};
use tokio::sync::OnceCell;
use uuid::Uuid;
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{Protocol, WarpgateError};
use warpgate_core::AuthorizedIdentity;
use warpgate_db_entities::Parameters;

use crate::request::{trusted_host_header, trusted_proto};

/// Used to enforce the re-authentication policy (web_auth_max_age_seconds)
const AUTH_TIME_SESSION_KEY: &str = "auth_time";

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub fn stamp_session_auth_time(session: &Session) {
    session.set(AUTH_TIME_SESSION_KEY, now_unix());
}

/// Checks web_auth_max_age_seconds policy
/// For sensitive endpoints (Web SSH start, ticket creation)
pub async fn web_reauth_required(
    ctx: &AuthenticatedRequestContext,
    session: &Session,
) -> Result<bool, WarpgateError> {
    if !matches!(
        ctx.auth,
        RequestAuthorization::Session(SessionAuthorization::User { .. })
    ) {
        return Ok(false);
    }

    let Some(max_age) = ctx.parameters().await?.web_auth_max_age_seconds else {
        return Ok(false);
    };

    let Some(auth_time) = session.get::<u64>(AUTH_TIME_SESSION_KEY) else {
        return Ok(true);
    };

    Ok(now_unix() - auth_time >= max_age.cast_unsigned())
}

/// Represents the source of authentication of a session
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum SessionAuthorization {
    User {
        user_id: Uuid,
        username: String,
    },
    Ticket {
        user_id: Uuid,
        username: String,
        /// The row the ticket was issued for. Pinned by id so a rename — or a
        /// new target claiming the old name — can't redirect the session.
        target_id: Uuid,
        #[serde(default)]
        ticket_id: Option<Uuid>,
    },
}

impl SessionAuthorization {
    pub const fn username(&self) -> &String {
        match self {
            Self::User { username, .. } | Self::Ticket { username, .. } => username,
        }
    }

    pub const fn user_id(&self) -> Uuid {
        match self {
            Self::User { user_id, .. } | Self::Ticket { user_id, .. } => *user_id,
        }
    }
}

/// Represents the source of authentication in a request
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum RequestAuthorization {
    Session(SessionAuthorization),
    UserToken {
        user_id: Uuid,
        username: String,
    },
    AdminToken,
    /// Auth between cluster peers
    ClusterToken,
}

#[derive(Clone)]
pub struct UnauthenticatedRequestContext {
    services: warpgate_core::Services,
    should_trust_x_forwarded: bool,
    /// Request-scoped cache of the global parameters row, loaded at most once
    /// per request on first access. The base context injected at startup is
    /// shared across requests, so [`Self::for_request`] gives each request its
    /// own empty cell to keep the snapshot request-scoped.
    parameters: Arc<OnceCell<Parameters::Model>>,
}

/// Provided to API handlers as Data<>
impl UnauthenticatedRequestContext {
    pub async fn new(services: warpgate_core::Services) -> Self {
        let should_trust_x_forwarded = services
            .config
            .lock()
            .await
            .store
            .http
            .trust_x_forwarded_headers;
        Self {
            services,
            should_trust_x_forwarded,
            parameters: Arc::new(OnceCell::new()),
        }
    }

    /// A copy for a single request, with a fresh empty parameter cache.
    #[must_use]
    pub fn for_request(&self) -> Self {
        Self {
            services: self.services.clone(),
            should_trust_x_forwarded: self.should_trust_x_forwarded,
            parameters: Arc::new(OnceCell::new()),
        }
    }

    pub const fn services(&self) -> &warpgate_core::Services {
        &self.services
    }

    /// The global parameters, cached for the duration of the request. Prefer
    /// this over `Parameters::Entity::get` in request handlers so a request
    /// reads the row at most once.
    pub async fn parameters(&self) -> Result<&Parameters::Model, WarpgateError> {
        self.parameters
            .get_or_try_init(|| async {
                Parameters::Entity::get(&self.services.db)
                    .await
                    .map_err(WarpgateError::from)
            })
            .await
    }

    pub fn to_authenticated(&self, auth: RequestAuthorization) -> AuthenticatedRequestContext {
        AuthenticatedRequestContext {
            auth,
            inner: self.clone(),
        }
    }

    /// Returns the trusted full Host header value (including port if present),
    /// preferring X-Forwarded-Host if trust_x_forwarded_headers is enabled in config.
    fn parse_host_authority(host_header: &str) -> Option<Authority> {
        host_header.parse::<Authority>().ok()
    }

    pub fn trusted_host_header(&self, req: &Request) -> Option<String> {
        trusted_host_header(self.should_trust_x_forwarded, req)
    }

    /// Returns the trusted hostname only (port stripped),
    /// preferring X-Forwarded-Host if trust_x_forwarded_headers is enabled in config.
    pub fn trusted_hostname(&self, req: &Request) -> Option<String> {
        let host_header = self.trusted_host_header(req)?;
        Self::parse_host_authority(&host_header).map(|authority| authority.host().to_string())
    }

    /// Returns the trusted port only,
    /// preferring X-Forwarded-Host if trust_x_forwarded_headers is enabled in config.
    pub fn trusted_port(&self, req: &Request) -> Option<u16> {
        let host_header = self.trusted_host_header(req)?;
        Self::parse_host_authority(&host_header).and_then(|authority| authority.port_u16())
    }

    /// Returns the trusted protocol scheme for the request, preferring X-Forwarded-Proto
    /// if trust_x_forwarded_headers is enabled in config.
    pub fn trusted_proto(&self, req: &Request) -> Scheme {
        trusted_proto(self.should_trust_x_forwarded, req)
    }
}

#[derive(Clone)]
/// Provided to API handlers as Data<> when a request is authenticated
pub struct AuthenticatedRequestContext {
    pub auth: RequestAuthorization,
    inner: UnauthenticatedRequestContext,
}

impl Deref for AuthenticatedRequestContext {
    type Target = UnauthenticatedRequestContext;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Proof that the caller is acting as a full user and not a ticket
/// Created only by RequestAuthorization::as_full_user
/// (compile time enforcement)
#[derive(Debug, Clone)]
pub struct FullUserAuthorization(AuthStateUserInfo);

impl FullUserAuthorization {
    pub const fn user_id(&self) -> Uuid {
        self.0.id
    }

    pub fn username(&self) -> &str {
        &self.0.username
    }

    pub fn identity(&self, protocol: Protocol) -> AuthorizedIdentity {
        AuthorizedIdentity::for_authenticated_session(self.0.clone(), protocol)
    }
}

/// The names `attribution()` gives to the two tokens, and the names no user may
/// have.
///
/// Exported so the admin API can refuse them: `attribution()` returns these
/// into the certificate key ID, which the target's sshd log carries verbatim,
/// and nothing stopped an admin creating a user called `admin-token`. A session
/// opened by that person and one opened by the admin API token then read
/// identically in the target's log and in Vault's audit log — the two records
/// this feature exists to make trustworthy.
pub const TOKEN_ATTRIBUTIONS: [&str; 2] = ["admin-token", "cluster-token"];

impl RequestAuthorization {
    /// Returns a username if one is present (admin token has none)
    pub const fn username(&self) -> Option<&String> {
        match self {
            Self::Session(auth) => Some(auth.username()),
            Self::UserToken { username, .. } => Some(username),
            Self::AdminToken | Self::ClusterToken => None,
        }
    }

    /// A name for a log that is not ours, honest for every variant.
    ///
    /// `username()` returns `None` for a token, and the one caller that needed
    /// a name substituted the literal string "admin" — so a certificate minted
    /// by an API token was recorded, in the target's own sshd log and in
    /// Vault's issuance log, as though a person called "admin" had opened the
    /// session. That is the attribution failure the certificate feature exists
    /// to prevent, reintroduced by the change that was meant to fix it.
    ///
    /// A token is not a person and this says so.
    pub fn attribution(&self) -> &str {
        match self {
            Self::Session(auth) => auth.username(),
            Self::UserToken { username, .. } => username,
            Self::AdminToken => TOKEN_ATTRIBUTIONS[0],
            Self::ClusterToken => TOKEN_ATTRIBUTIONS[1],
        }
    }

    /// Whether `attribution()` names the gateway rather than a person.
    ///
    /// `username()` already draws this line — it is `None` for exactly the two
    /// token variants. This asks a different question with the same answer: not
    /// "who is the user" but "is this string ours, to be kept verbatim".
    #[must_use]
    pub const fn attribution_is_gateway(&self) -> bool {
        matches!(self, Self::AdminToken | Self::ClusterToken)
    }

    /// Returns a user ID if present in the authorization context or nil UUID
    pub const fn user_id(&self) -> Uuid {
        match self {
            Self::Session(auth) => auth.user_id(),
            Self::UserToken { user_id, .. } => *user_id,
            Self::AdminToken | Self::ClusterToken => Uuid::nil(),
        }
    }

    /// Ticket requests cannot grant access to user-scoped functions such as cred management.
    /// Type safety chokepoint - only this produces [FullUserAuthorization]
    pub fn as_full_user(&self) -> Option<FullUserAuthorization> {
        match self {
            Self::Session(SessionAuthorization::User { user_id, username })
            | Self::UserToken { user_id, username } => {
                Some(FullUserAuthorization(AuthStateUserInfo {
                    id: *user_id,
                    username: username.clone(),
                }))
            }
            Self::Session(SessionAuthorization::Ticket { .. })
            | Self::AdminToken
            | Self::ClusterToken => None,
        }
    }
}

/// Check if a host is localhost or 127.x.x.x (for development/testing scenarios)
pub fn is_localhost_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host.starts_with("127.")
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::{RequestAuthorization, SessionAuthorization};

    #[test]
    fn only_full_accounts_are_full_users() {
        // A ticket is scoped to a single target: it must never resolve to a
        // full account, or credential/token/admin endpoints would be reachable
        // with it.
        let ticket = RequestAuthorization::Session(SessionAuthorization::Ticket {
            user_id: Uuid::nil(),
            username: "alice".into(),
            target_id: Uuid::nil(),
            ticket_id: None,
        });
        assert!(ticket.as_full_user().is_none());

        // A user session and a user's API token are full accounts.
        let user = RequestAuthorization::Session(SessionAuthorization::User {
            user_id: Uuid::nil(),
            username: "alice".into(),
        });
        assert!(user.as_full_user().is_some());

        let token = RequestAuthorization::UserToken {
            user_id: Uuid::nil(),
            username: "alice".into(),
        };
        assert!(token.as_full_user().is_some());

        // Machine tokens carry no user identity.
        assert!(RequestAuthorization::AdminToken.as_full_user().is_none());
        assert!(RequestAuthorization::ClusterToken.as_full_user().is_none());
    }
}
