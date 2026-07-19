use std::ops::Deref;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use poem::Request;
use poem::http::uri::{Authority, Scheme};
use poem::session::Session;
use serde::{Deserialize, Serialize};
use tokio::sync::OnceCell;
use uuid::Uuid;
use warpgate_common::WarpgateError;
use warpgate_db_entities::Parameters;

use crate::request::{trusted_host_header, trusted_proto};

/// Used to enforce the re-authentication policy (web_auth_max_age_seconds)
const AUTH_TIME_SESSION_KEY: &str = "auth_time";

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthStateId(pub Uuid);

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
        target_name: String,
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
    /// Auth between cluster peers.
    ///
    /// Carries the authorization the request had on the node that forwarded it,
    /// so the owning node can attribute what it does on that node's behalf —
    /// the cluster token authenticates the *peer*, not the person behind it.
    /// Required on every forwarded request: a cluster-authenticated call with
    /// no origin is an action nobody can be held to, so it is rejected rather
    /// than logged as anonymous.
    ///
    /// This never confers permissions. `has_admin_permission` still refuses a
    /// cluster token outright; the origin node authorizes the admin before
    /// forwarding, and `require_cluster_or_admin_permission` is what accepts
    /// the result.
    ClusterToken {
        origin: Box<RequestAuthorization>,
    },
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

impl RequestAuthorization {
    /// Returns a username if one is present (admin token has none)
    pub const fn username(&self) -> Option<&String> {
        match self {
            Self::Session(auth) => Some(auth.username()),
            Self::UserToken { username, .. } => Some(username),
            Self::AdminToken | Self::ClusterToken { .. } => None,
        }
    }

    /// Returns a user ID if present in the authorization context or nil UUID
    pub const fn user_id(&self) -> Uuid {
        match self {
            Self::Session(auth) => auth.user_id(),
            Self::UserToken { user_id, .. } => *user_id,
            Self::AdminToken | Self::ClusterToken { .. } => Uuid::nil(),
        }
    }

    /// The authorization to *attribute* this request to: for a cluster-forwarded
    /// request the one it had on the originating node, otherwise this one.
    ///
    /// Deliberately separate from [`Self::username`] and [`Self::user_id`],
    /// which keep reporting nothing for a cluster token. A forwarded identity
    /// says who asked for an action, never what they may do, so it is only
    /// reachable where a caller explicitly wants to name an actor.
    pub fn actor(&self) -> &Self {
        match self {
            // Flattened: a chain of forwards still attributes to whoever
            // originally asked.
            Self::ClusterToken { origin } => origin.actor(),
            other => other,
        }
    }
}

/// Check if a host is localhost or 127.x.x.x (for development/testing scenarios)
pub fn is_localhost_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host.starts_with("127.")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(name: &str) -> RequestAuthorization {
        RequestAuthorization::Session(SessionAuthorization::User {
            user_id: Uuid::from_u128(1),
            username: name.to_owned(),
        })
    }

    #[test]
    fn cluster_actor_survives_a_round_trip() {
        let encoded = crate::encode_cluster_actor(&user("alice")).unwrap();
        let decoded = crate::decode_cluster_actor(&encoded).unwrap();
        assert_eq!(decoded.username().map(String::as_str), Some("alice"));
    }

    #[test]
    fn garbage_actor_headers_are_rejected() {
        // The auth path turns `None` into a 401, so anything unreadable must
        // not decode into some default identity.
        assert!(crate::decode_cluster_actor("not base64!").is_none());
        assert!(crate::decode_cluster_actor("YWJj").is_none());
    }

    #[test]
    fn a_cluster_token_reports_no_identity_of_its_own() {
        let auth = RequestAuthorization::ClusterToken {
            origin: Box::new(user("alice")),
        };
        // Permission checks must never see the forwarded user...
        assert_eq!(auth.username(), None);
        assert!(auth.user_id().is_nil());
        // ...but attribution must.
        assert_eq!(auth.actor().username().map(String::as_str), Some("alice"));
    }

    #[test]
    fn actor_flattens_nested_forwards() {
        let auth = RequestAuthorization::ClusterToken {
            origin: Box::new(RequestAuthorization::ClusterToken {
                origin: Box::new(user("alice")),
            }),
        };
        assert_eq!(auth.actor().username().map(String::as_str), Some("alice"));
    }
}
