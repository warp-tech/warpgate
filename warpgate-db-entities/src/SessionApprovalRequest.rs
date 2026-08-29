use sea_orm::entity::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::auth::{ApprovalKind, ApprovalScope};
use warpgate_common::{NodeId, UserSessionId};

#[derive(Debug, PartialEq, Eq, Clone, Copy, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum ApprovalRequestStatus {
    #[sea_orm(string_value = "pending")]
    Pending,
    #[sea_orm(string_value = "approved")]
    Approved,
    #[sea_orm(string_value = "rejected")]
    Rejected,
    /// nobody answered the approval
    #[sea_orm(string_value = "timed_out")]
    TimedOut,
    /// the connection died before the approval got answered
    #[sea_orm(string_value = "abandoned")]
    Abandoned,
}

impl ApprovalRequestStatus {
    // states that
    /// Terminal states that carry no decision, and so answer nothing. A row in
    /// one of these is history: a later gate on the same session reopens it.
    pub const UNANSWERED: [Self; 2] = [Self::TimedOut, Self::Abandoned];
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
/// Keyed by `(session_id, kind, target)`: a question is about one session
/// reaching one target, and a session that reaches several holds one row each.
/// The target is part of the key rather than a column so that asking about a
/// second target cannot overwrite the answer given about the first — the two
/// are different questions and each keeps its own record.
///
/// Within one key, creation is idempotent: a wait site that runs twice upserts
/// its own row instead of queueing a duplicate, and a row left over from an
/// earlier, finished gate on the same target is reopened rather than
/// duplicated.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "session_approval_requests")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub session_id: UserSessionId,
    #[sea_orm(primary_key, auto_increment = false)]
    pub kind: ApprovalKind,
    /// The node running the session that is waiting (the row's creator).
    pub node_id: NodeId,
    pub protocol: String,
    pub username: String,
    /// The user whose session is being asked about. Stored alongside the name
    /// so a decision can be attributed to them in the audit trail without a
    /// lookup, mirroring `resolved_by_user_id` for the approver.
    pub user_id: Uuid,
    /// Part of the key: see the type docs.
    #[sea_orm(primary_key, auto_increment = false)]
    pub target: String,
    pub remote_address: Option<String>,
    /// The short code the user is shown, for confirming they are approving
    /// their own login. Only [`ApprovalKind::User`] has one — an
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
    pub scope: Option<ApprovalScope>,
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
    /// Columns rewritten when a request is re-advertised or reopened (upsert_request)
    pub const IDENTITY: [Self; 9] = [
        Self::NodeId,
        Self::Protocol,
        Self::Username,
        Self::UserId,
        Self::RemoteAddress,
        Self::IdentificationString,
        Self::CredentialsDigest,
        Self::ConsumesTicketId,
        Self::Started,
    ];

    /// Everything else (decision record), overwritten only on a reopen
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
