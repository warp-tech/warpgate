use std::ops::Deref;

use poem::Request;
use poem::http::header::HOST;
use poem::http::uri::{Authority, Scheme};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use warpgate_common::http_headers::{X_FORWARDED_HOST, X_FORWARDED_PROTO};

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
    UserToken { user_id: Uuid, username: String },
    AdminToken,
}

#[derive(Clone)]
pub struct UnauthenticatedRequestContext {
    services: warpgate_core::Services,
    should_trust_x_forwarded: bool,
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
        }
    }

    pub const fn services(&self) -> &warpgate_core::Services {
        &self.services
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
        if self.should_trust_x_forwarded
            && let Some(xfh) = req.header(&X_FORWARDED_HOST)
        {
            Some(xfh.to_string())
        } else {
            req.header(HOST).map(ToString::to_string).or_else(|| {
                let uri = req.original_uri();
                uri.authority().map(|authority| authority.to_string())
            })
        }
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
        if self.should_trust_x_forwarded
            && let Some(proto) = req.header(&X_FORWARDED_PROTO)
            && let Ok(s) = Scheme::try_from(proto)
        {
            s
        } else {
            req.original_uri()
                .scheme()
                .cloned()
                .unwrap_or(Scheme::HTTPS)
        }
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
            Self::AdminToken => None,
        }
    }

    /// Returns a user ID if present in the authorization context.
    pub const fn user_id(&self) -> Uuid {
        match self {
            Self::Session(auth) => auth.user_id(),
            Self::UserToken { user_id, .. } => *user_id,
            Self::AdminToken => Uuid::nil(),
        }
    }
}

/// Check if a host is localhost or 127.x.x.x (for development/testing scenarios)
pub fn is_localhost_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host.starts_with("127.")
}
