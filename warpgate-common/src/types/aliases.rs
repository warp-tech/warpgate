use poem_openapi::NewType;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Deliberately no `From<Uuid>`: a bare `.into()` would let a user-session id
// pass where a target-session id belongs (and vice versa). Wrapping is an
// explicit `$name(uuid)` at the boundary where the id's origin is visible.
// TODO reuse for other IDs
macro_rules! uuid_newtype {
    ($(#[$attr:meta])* $name:ident) => {
        $(#[$attr])*
        #[derive(
            Debug,
            Clone,
            Copy,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            Serialize,
            Deserialize,
            NewType,
        )]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }

        impl From<$name> for Uuid {
            fn from(id: $name) -> Self {
                id.0
            }
        }

        impl std::ops::Deref for $name {
            type Target = Uuid;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
    };
}

uuid_newtype!(UserSessionId);
uuid_newtype!(TargetSessionId);
uuid_newtype!(
    /// A cluster node's ephemeral identity (random per process start). The
    /// nil UUID is the legacy "no owning node" sentinel in stored rows and
    /// must never be treated as a reachable peer — `node_owner` is the one
    /// place that decodes it.
    NodeId
);

/// Identity of a Warpgate protocol. Used wherever code branches on the
/// protocol (credential policies, auth states) so that a protocol can't be
/// misspelled or silently unmatched; the wire/DB/audit string form is
/// [`Protocol::name`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Http,
    Ssh,
    MySql,
    Postgres,
    Kubernetes,
    Vnc,
    Rdp,
}

/// How one user session lives and dies. Chosen by the code that registers the
/// session — not by its protocol, which cannot know what keeps a particular
/// session alive — and stamped into the row (`user_sessions.node_id`), so the
/// reaper and teardown read the row itself instead of re-deriving anything.
/// [`Protocol::lifecycle`] is the usual answer, but a protocol can register
/// sessions of either kind: an HTTP session held open by a node-local handle
/// rather than by a stored cookie is `ConnectionBound`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionLifecycle {
    /// The session is a runtime object on one node — a live connection, or
    /// in-memory correlation state. Its row records the owning node and the
    /// session ends when that node's registration lapses.
    ConnectionBound,
    /// The session is a database record served by any node behind the load
    /// balancer; no node owns it (`node_id` is NULL), so no node's death ends
    /// it. What does end it is named by the backing: whatever holds a
    /// reference to the session is what keeps it alive.
    Shared(SharedSessionBacking),
}

/// What a shared-lifecycle session's liveness is read from. A new variant is a
/// promise that the reaper knows how to tell whether such a session is still
/// referenced — without one it would be ended the moment its grace expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedSessionBacking {
    /// A stored browser session in `http_sessions`; the session ends when no
    /// stored cookie session references it anymore.
    CookieSession,
}

impl Protocol {
    /// Every protocol, so a sweep that has to act per protocol can't quietly
    /// omit one.
    pub const ALL: [Self; 7] = [
        Self::Http,
        Self::Ssh,
        Self::MySql,
        Self::Postgres,
        Self::Kubernetes,
        Self::Vnc,
        Self::Rdp,
    ];

    /// How this protocol's sessions live and die by default. Registration
    /// takes the lifecycle as an argument, so a session kept alive by
    /// something other than its protocol's usual backing says so there.
    pub const fn lifecycle(self) -> SessionLifecycle {
        match self {
            Self::Http => SessionLifecycle::Shared(SharedSessionBacking::CookieSession),
            // Kubernetes traffic is load-balanced too, but a Kubernetes
            // session *is* a runtime object: the request correlator and the
            // pending-approval auth state are in-memory on one node, and the
            // session row's node is what routes approvals there. Making it
            // Shared requires DB-backed request correlation first.
            Self::Kubernetes | Self::Ssh | Self::MySql | Self::Postgres | Self::Vnc | Self::Rdp => {
                SessionLifecycle::ConnectionBound
            }
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Http => "HTTP",
            Self::Ssh => "SSH",
            Self::MySql => "MySQL",
            Self::Postgres => "PostgreSQL",
            Self::Kubernetes => "Kubernetes",
            Self::Vnc => "VNC",
            Self::Rdp => "RDP",
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}
