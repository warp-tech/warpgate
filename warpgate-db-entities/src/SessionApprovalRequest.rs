use sea_orm::entity::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::auth::ApprovalKind;
use warpgate_common::{NodeId, UserSessionId};

/// Which out-of-band approval factor a request is waiting on.
#[derive(Debug, PartialEq, Eq, Clone, Copy, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum ApprovalRequestKind {
    #[sea_orm(string_value = "user")]
    User,
    #[sea_orm(string_value = "admin")]
    Admin,
}

impl From<ApprovalKind> for ApprovalRequestKind {
    fn from(kind: ApprovalKind) -> Self {
        match kind {
            ApprovalKind::User => Self::User,
            ApprovalKind::Admin => Self::Admin,
        }
    }
}

/// Where a request has got to. The decision lives on the row, so any node can
/// record it and the owning node reads it back.
///
/// Everything but [`Pending`] is terminal. The two that carry no decision are
/// kept apart because the difference is the whole audit answer: nobody answered
/// in time, versus nobody was left to answer for.
///
/// [`Pending`]: Self::Pending
#[derive(Debug, PartialEq, Eq, Clone, Copy, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum ApprovalRequestStatus {
    #[sea_orm(string_value = "pending")]
    Pending,
    #[sea_orm(string_value = "approved")]
    Approved,
    #[sea_orm(string_value = "rejected")]
    Rejected,
    /// The approval window ran out before anyone decided.
    #[sea_orm(string_value = "timed_out")]
    TimedOut,
    /// The connection waiting on it went away first — the client left, the
    /// session ended, or the owning node did.
    #[sea_orm(string_value = "abandoned")]
    Abandoned,
}

impl ApprovalRequestStatus {
    /// Terminal states that carry no decision, and so answer nothing. A row in
    /// one of these is history: a later gate on the same session reopens it.
    pub const UNANSWERED: [Self; 2] = [Self::TimedOut, Self::Abandoned];
}

/// How widely an approval is remembered for later bypass.
#[derive(Debug, PartialEq, Eq, Clone, Copy, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum ApprovalRequestScope {
    #[sea_orm(string_value = "once")]
    Once,
    #[sea_orm(string_value = "target")]
    Target,
    #[sea_orm(string_value = "all_targets")]
    AllTargets,
}

/// An out-of-band approval request — a first-class record, not a projection:
/// the wait site on the owning node creates it when an approval becomes needed,
/// and it carries the decision as well as the question. Any node can resolve a
/// request by writing the decision to its row; the owning node, the only one
/// that can act on it, reads it back from there.
///
/// Rows are never deleted while they matter — they are moved to a terminal
/// status instead, and pruned only by `cleanup_db` at the audit retention. So
/// the table is the approval audit trail, and a gate can always tell "answered
/// and I missed it" from "no longer a live question"; a vanishing row could
/// only ever be read as the latter.
///
/// Keyed by `(session_id, kind)`: a session waits on at most one approval of
/// each kind at a time, which makes creation idempotent — a wait site that runs
/// twice upserts the same row instead of queueing a duplicate. A row left over
/// from an earlier, finished gate on the same session is reopened rather than
/// duplicated.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "session_approval_requests")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub session_id: UserSessionId,
    #[sea_orm(primary_key, auto_increment = false)]
    pub kind: ApprovalRequestKind,
    /// The node running the session that is waiting (the row's creator).
    pub node_id: NodeId,
    pub protocol: String,
    pub username: String,
    pub target: String,
    pub remote_address: Option<String>,
    /// The short code the user is shown, for confirming they are approving
    /// their own login. Only [`ApprovalRequestKind::User`] has one — an
    /// administrator approval is a gate on a connection, with no second party
    /// reading a code off a screen.
    pub identification_string: Option<String>,
    /// A digest of the credentials the session authenticated with, so an
    /// approved row can be matched against a later identical connection for
    /// the grace-period bypass. Null when the session has nothing stable to
    /// pin a grant to — then the row can never serve as a remembered approval.
    pub credentials_digest: Option<String>,
    /// The ticket to consume if this request is approved. Set only where a
    /// ticket's consumption is deferred to the gate (an HTTP ticket session,
    /// whose session outlives any one request); connection-holding protocols
    /// settle their ticket through the gate outcome instead.
    pub consumes_ticket_id: Option<Uuid>,
    pub started: OffsetDateTime,
    pub status: ApprovalRequestStatus,
    /// Set alongside [`ApprovalRequestStatus::Approved`].
    pub scope: Option<ApprovalRequestScope>,
    pub resolved_by_username: Option<String>,
    /// Null when the resolver isn't a user, such as the admin API token.
    pub resolved_by_user_id: Option<Uuid>,
    /// When the question left [`ApprovalRequestStatus::Pending`], however it
    /// did. For an approval this anchors the grace-period window.
    pub resolved_at: Option<OffsetDateTime>,
    /// When the owning node read the decision back and acted on it. Null while
    /// the request is still a live question, which is what keeps the node-wide
    /// sweep from re-applying a decision it has already delivered.
    pub consumed_at: Option<OffsetDateTime>,
}

impl Column {
    /// The question: who is asking, from where, about what. Rewritten wholesale
    /// whenever the row is re-advertised or a finished request is reopened.
    ///
    /// Every non-key column belongs to exactly this set or [`Self::DECISION`] —
    /// a new column must be added to one of them so the reopen/takeover paths
    /// handle it (enforced by a test in `warpgate_core::approvals`).
    pub const IDENTITY: [Self; 9] = [
        Self::NodeId,
        Self::Protocol,
        Self::Username,
        Self::Target,
        Self::RemoteAddress,
        Self::IdentificationString,
        Self::CredentialsDigest,
        Self::ConsumesTicketId,
        Self::Started,
    ];

    /// The answer: how the question ended, who ended it, and whether the owner
    /// picked it up. Reset when a row is reopened for a new question, and never
    /// overwritten while the question stands.
    pub const DECISION: [Self; 6] = [
        Self::Status,
        Self::Scope,
        Self::ResolvedByUsername,
        Self::ResolvedByUserId,
        Self::ResolvedAt,
        Self::ConsumedAt,
    ];
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
