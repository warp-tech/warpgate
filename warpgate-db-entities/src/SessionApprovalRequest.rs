use sea_orm::entity::prelude::*;
use sea_orm::sea_query::{IntoCondition, OnConflict, SimpleExpr};
use sea_orm::{Condition, QueryFilter, Set};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::auth::{ApprovalKind, ApprovalScope};
use warpgate_common::{NodeId, UserSessionId, WarpgateError};

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
    /// Columns rewritten when a request is re-advertised or reopened ([`upsert_request`])
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

// --- Request rows ---------------------------------------------------------
//
// The queries and writes over this table, kept beside the columns and the
// IDENTITY/DECISION partition they have to respect. What a request *means* —
// who waits on one, what a decision does to a connection — lives in
// `warpgate_core::approvals`.
/// The request of one kind on a session, where only one can exist: a login has
/// a single target name fixed when its auth state is built, so its own approval
/// is unambiguous. Administrator gates name their target — see
/// [`find_question`].
pub async fn find_request(
    db: &DatabaseConnection,
    session_id: UserSessionId,
    kind: ApprovalKind,
) -> Result<Option<Model>, WarpgateError> {
    Ok(Entity::find()
        .filter(one_request(session_id, kind))
        .one(db)
        .await?)
}

/// [`find_request`], narrowed to one question: `None` also when the slot has
/// been taken over by a question about a different target.
pub async fn find_question(
    db: &DatabaseConnection,
    session_id: UserSessionId,
    kind: ApprovalKind,
    target: &str,
) -> Result<Option<Model>, WarpgateError> {
    Ok(Entity::find()
        .filter(one_question(session_id, kind, target))
        .one(db)
        .await?)
}

/// A status change on request rows, and the only thing in this module that
/// writes [`Column::Status`].
///
/// There is no constructor that doesn't name the states it may leave. That is
/// the whole point: every write here is a close of some kind, and a close that
/// forgot to exclude `Approved`/`Rejected` would erase an answer an
/// administrator had already given — the session would then wait out its window
/// while the inbox kept offering it again. Making the guard part of building the
/// statement means a new close site cannot be written without one.
///
/// The one status write that doesn't go through this is the reopen in
/// [`upsert_request`], which rewrites every column and so builds its statement
/// from the model; it names its own source states inline.
pub struct StatusTransition {
    to: ApprovalRequestStatus,
    /// Which rows this transition is allowed to leave.
    from: Condition,
    /// Columns written alongside the status.
    columns: Vec<(Column, SimpleExpr)>,
}

impl StatusTransition {
    /// The ordinary case: a request still waiting on an answer. Every way out
    /// of `Pending` goes through here, so the transition also stamps when the
    /// question was resolved — for an approval, that is what anchors the
    /// grace-period window.
    pub fn from_pending(to: ApprovalRequestStatus) -> Self {
        Self {
            to,
            from: Column::Status
                .eq(ApprovalRequestStatus::Pending)
                .into_condition(),
            columns: vec![(Column::ResolvedAt, OffsetDateTime::now_utc().into())],
        }
    }

    pub fn set(mut self, column: Column, value: impl Into<SimpleExpr>) -> Self {
        self.columns.push((column, value.into()));
        self
    }

    /// Applies to every row matching `which` that is also in an allowed source
    /// state. Returns how many rows moved.
    pub async fn apply(
        self,
        db: &DatabaseConnection,
        which: Condition,
    ) -> Result<u64, WarpgateError> {
        let mut query = Entity::update_many()
            .col_expr(Column::Status, self.to.into())
            .filter(which)
            .filter(self.from);
        for (column, value) in self.columns {
            query = query.col_expr(column, value);
        }
        Ok(query.exec(db).await?.rows_affected)
    }
}

/// Every request of one kind on a session, across its targets.
pub fn one_request(session_id: UserSessionId, kind: ApprovalKind) -> Condition {
    Column::SessionId
        .eq(session_id)
        .and(Column::Kind.eq(kind))
        .into_condition()
}

/// One *question*: [`one_request`] narrowed to the target it asks about — the
/// full key, which everything that answers, consumes or closes a question must
/// name so it cannot touch the session's other questions.
pub fn one_question(session_id: UserSessionId, kind: ApprovalKind, target: &str) -> Condition {
    one_request(session_id, kind).add(Column::Target.eq(target))
}

/// Row key: (session_id, kind, target)
///
/// `, so a wait site that runs
/// twice for the same question updates its own row instead of queueing a
/// duplicate, and a question about another target is simply another row.
///
/// A decision nobody has picked up yet is deliberately left alone.
/// Re-advertising is the same session asking the same question again — a
/// request/response protocol re-enters its gate on every request — and an
/// answer given between two of those is the answer to *this* question.
/// Rewriting it would silently discard a decision an administrator has already
/// made.
///
/// A row that ended *without* an answer is a previous asking of the same
/// question and is always reopened — there is no decision to lose, and the
/// session is legitimately asking again. What a row that does carry a decision
/// means is [`DecidedRow`], because it differs by kind.
pub enum DecidedRow {
    /// The decision stands, and a fresh asking of the same question reuses it
    /// rather than putting it to anyone again.
    ///
    /// This is administrator approval, where the question is whether a user
    /// session may reach a target. `(user_session_id, target_id)` is unique and
    /// a target session is only ever ended along with its parent, so an admitted
    /// session keeps its open access row and never reaches the gate a second
    /// time. Were it to anyway, the answer it already has is the right one.
    Reuse,
    /// The decision answered a *previous* asking, and must not be read as this
    /// one's — the row is reopened and the question put again.
    ///
    /// This is self approval, where the question is whether a login is really
    /// the user. A retried login reuses the session id it failed under, so one
    /// key genuinely carries a succession of questions.
    Reopen,
}

pub async fn upsert_request(
    db: &DatabaseConnection,
    row: ActiveModel,
    decided: DecidedRow,
) -> Result<(), WarpgateError> {
    use self::ApprovalRequestStatus as Status;

    let mut reopened = row.clone();
    // Same row, decision cleared out
    reopened.status = Set(Status::Pending);
    reopened.scope = Set(None);
    reopened.resolved_by_username = Set(None);
    reopened.resolved_by_user_id = Set(None);
    reopened.resolved_at = Set(None);
    reopened.consumed_at = Set(None);

    let mut still_a_question = Condition::any()
        // Ended without an answer (timed out / abandoned)
        .add(Column::Status.is_in(ApprovalRequestStatus::UNANSWERED))
        // OR is still pending
        .add(Column::Status.eq(Status::Pending));
    if matches!(decided, DecidedRow::Reopen) {
        still_a_question = still_a_question.add(Column::ConsumedAt.is_not_null());
    }

    match Entity::update(reopened)
        .filter(still_a_question)
        .exec(db)
        .await
    {
        // Found an existing reusable request and updated it
        Ok(_) => return Ok(()),
        // Nothing usable found, continue
        Err(DbErr::RecordNotUpdated) => {}
        Err(error) => return Err(error.into()),
    }

    match Entity::insert(row)
        .on_conflict(
            OnConflict::columns([Column::SessionId, Column::Kind, Column::Target])
                // Re-assigning a key column the value it already holds is the
                // portable way to say "leave this row alone": `do_nothing()`
                // builds `ON DUPLICATE KEY IGNORE` for MySQL, which is not SQL.
                .update_column(Column::SessionId)
                .to_owned(),
        )
        .exec(db)
        .await
    {
        Ok(_) => Ok(()),
        // The standing answer the update declined to touch, or a row another
        // node advertised in between — current either way, and not this call's
        // to overwrite.
        Err(DbErr::RecordNotInserted) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Ends a request that is still waiting, leaving the row as the record of how.
///
/// Only a pending request can be closed this way: a decision already written to
/// the row is the answer, and outranks whatever the waiting side went on to do.
/// `target` names the question being closed, so a straggling close cannot end a
/// successor question that has since taken the slot over.
pub async fn close_request(
    db: &DatabaseConnection,
    session_id: UserSessionId,
    kind: ApprovalKind,
    target: &str,
    status: ApprovalRequestStatus,
) -> Result<(), WarpgateError> {
    StatusTransition::from_pending(status)
        .apply(db, one_question(session_id, kind, target))
        .await?;
    Ok(())
}

/// Records that the owning node has read a decision off the row and acted on
/// it. The row stays as the audit record; the stamp is what takes it out of the
/// self-approval sweep, and what tells a later asking of a [`DecidedRow::Reopen`]
/// question that the answer it can see belongs to an earlier one. `which` names
/// the rows — [`one_question`] where the caller knows which question it
/// delivered, [`one_request`] where the state, not the row, was the authority.
pub async fn mark_consumed(db: &DatabaseConnection, which: Condition) -> Result<(), WarpgateError> {
    use Column;

    Entity::update_many()
        .col_expr(Column::ConsumedAt, OffsetDateTime::now_utc().into())
        .filter(which)
        .filter(Column::ConsumedAt.is_null())
        .exec(db)
        .await?;
    Ok(())
}

/// Ends every request still waiting on a session, for when the session itself
/// ends — the waiting connection is gone, so nothing can consume them.
pub async fn abandon_requests_for_session(
    db: &DatabaseConnection,
    session_id: UserSessionId,
) -> Result<(), WarpgateError> {
    StatusTransition::from_pending(ApprovalRequestStatus::Abandoned)
        .apply(db, Column::SessionId.eq(session_id).into_condition())
        .await?;
    Ok(())
}

/// Self approvals decided somewhere in the cluster that the node holding the
/// auth state has yet to act on. Rows stay behind as audit records once they
/// have been, so the `consumed_at` stamp — not the row's absence — is what
/// stops the same decision being delivered every tick.
pub async fn find_undelivered_user_decisions(
    db: &DatabaseConnection,
    node_id: NodeId,
) -> Result<Vec<Model>, WarpgateError> {
    Ok(Entity::find()
        .filter(Column::Kind.eq(ApprovalKind::User))
        .filter(Column::NodeId.eq(node_id))
        .filter(Column::Status.is_in([
            ApprovalRequestStatus::Approved,
            ApprovalRequestStatus::Rejected,
        ]))
        .filter(Column::ConsumedAt.is_null())
        .all(db)
        .await?)
}

/// Ends every request still pending that was asked before `cutoff`, for
/// waiters that are gone without having closed their own (owning node crashed,
/// or a `Drop` that never got to run). How old is too old is a policy question
/// and belongs to the caller.
pub async fn abandon_asked_before(
    db: &DatabaseConnection,
    cutoff: OffsetDateTime,
) -> Result<(), WarpgateError> {
    StatusTransition::from_pending(ApprovalRequestStatus::Abandoned)
        .apply(db, Column::Started.lt(cutoff).into_condition())
        .await?;
    Ok(())
}

/// Drops request rows past the audit retention. The only thing that deletes
/// one: everything else moves a request to a terminal status and leaves it as
/// the record of what was asked and who answered.
pub async fn prune_before(
    db: &DatabaseConnection,
    cutoff: OffsetDateTime,
) -> Result<(), WarpgateError> {
    Entity::delete_many()
        .filter(Column::Started.lt(cutoff))
        .exec(db)
        .await?;
    Ok(())
}
