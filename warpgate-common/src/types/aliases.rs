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

/// How a protocol's user sessions live and die. Stamped into each session row
/// at registration (`user_sessions.node_id`), so the reaper and teardown read
/// the row itself instead of re-deriving protocol semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionLifecycle {
    /// The session is a runtime object on one node — a live connection, or
    /// in-memory correlation state. Its row records the owning node and the
    /// session ends when that node's registration lapses.
    ConnectionBound,
    /// The session is a database record served by any node behind the load
    /// balancer; no node owns it (`node_id` is NULL). It ends by its own
    /// rules — for HTTP, when no stored cookie session references it anymore.
    Shared,
}

impl Protocol {
    pub const fn lifecycle(self) -> SessionLifecycle {
        match self {
            Self::Http => SessionLifecycle::Shared,
            // Kubernetes traffic is load-balanced too, but a Kubernetes
            // session *is* a runtime object: the request correlator and the
            // pending-approval auth state are in-memory on one node, and the
            // session row's node is what routes approvals there. Making it
            // Shared requires DB-backed request correlation first.
            Self::Kubernetes
            | Self::Ssh
            | Self::MySql
            | Self::Postgres
            | Self::Vnc
            | Self::Rdp => SessionLifecycle::ConnectionBound,
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
