use std::ops::Deref;

use sea_orm::entity::prelude::*;
use sea_orm::sea_query::{IntoCondition, SimpleExpr};
use sea_orm::{Condition, NotSet, QueryFilter, Set, SqlErr};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::auth::{ApprovalKind, ApprovalScope};
use warpgate_common::helpers::username::username_eq_ci;
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
    /// terminal states w/o decision (can be reopened)
    pub const UNANSWERED: [Self; 2] = [Self::TimedOut, Self::Abandoned];

    /// terminal states w/ decision (final)
    pub const DECIDED: [Self; 2] = [Self::Approved, Self::Rejected];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UndecidedApprovalRequestStatus {
    TimedOut,
    Abandoned,
}

impl From<UndecidedApprovalRequestStatus> for ApprovalRequestStatus {
    fn from(value: UndecidedApprovalRequestStatus) -> Self {
        match value {
            UndecidedApprovalRequestStatus::TimedOut => Self::TimedOut,
            UndecidedApprovalRequestStatus::Abandoned => Self::Abandoned,
        }
    }
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
/// its own row instead of queueing a duplicate, and a gate that ended without
/// an answer leaves a row a later one asks again through rather than
/// duplicating. An answer, once given, is never rewritten.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "session_approval_requests")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub session_id: UserSessionId,
    #[sea_orm(primary_key, auto_increment = false)]
    pub kind: ApprovalKind,
    /// the node running the waiting AuthState
    pub node_id: NodeId,
    pub protocol: String,
    pub username: String,
    pub user_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub target: String,
    pub remote_address: Option<String>,
    /// only user approvals have these
    pub identification_string: Option<String>,
    /// digest of the `WebApprovalIdentity` this request was made under — who,
    /// from where, with what — which a later attempt is matched against for the
    /// grace-period bypass. None when there was nothing to pin a grant to.
    pub match_digest: Option<String>,
    /// The ticket use this question holds: spent when the question was opened,
    /// given back if it ends without an approval. None for sessions that did
    /// not authenticate with a ticket.
    pub ticket_id: Option<Uuid>,
    pub started: OffsetDateTime,
    pub status: ApprovalRequestStatus,
    pub scope: Option<ApprovalScope>,
    pub resolved_by_username: Option<String>,
    /// None when resolver isn't a user (e.g. API token)
    pub resolved_by_user_id: Option<Uuid>,
    pub resolved_at: Option<OffsetDateTime>,
    /// when the session has acknowledged the decision
    pub consumed_at: Option<OffsetDateTime>,
}

impl Column {
    /// rewritten when a request is re-advertised
    pub const IDENTITY: [Self; 9] = [
        Self::NodeId,
        Self::Protocol,
        Self::Username,
        Self::UserId,
        Self::RemoteAddress,
        Self::IdentificationString,
        Self::MatchDigest,
        Self::TicketId,
        Self::Started,
    ];

    /// everything else (decision record)
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
struct StatusTransition {
    to: ApprovalRequestStatus,
    /// a filter on start condition
    from: Condition,
    /// columns to write
    columns: Vec<(Column, SimpleExpr)>,
}

impl StatusTransition {
    fn from_pending(to: ApprovalRequestStatus) -> Self {
        Self {
            to,
            from: Column::Status
                .eq(ApprovalRequestStatus::Pending)
                .into_condition(),
            columns: vec![(Column::ResolvedAt, OffsetDateTime::now_utc().into())],
        }
    }

    fn set(mut self, column: Column, value: impl Into<SimpleExpr>) -> Self {
        self.columns.push((column, value.into()));
        self
    }

    /// returns change count
    async fn apply(
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

/// Condition guaranteed to key on primary key
#[derive(Clone)]
pub struct Key(Condition);

impl Key {
    pub fn new(session_id: UserSessionId, kind: ApprovalKind, target: &str) -> Self {
        Self(
            Column::SessionId
                .eq(session_id)
                .and(Column::Kind.eq(kind))
                .and(Column::Target.eq(target))
                .into_condition(),
        )
    }
}

impl IntoCondition for Key {
    fn into_condition(self) -> Condition {
        self.0
    }
}

impl Deref for Key {
    type Target = Condition;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub async fn find_user_approval(
    db: &DatabaseConnection,
    username: &str,
    session_id: UserSessionId,
) -> Result<Option<Model>, WarpgateError> {
    let row = Entity::find()
        .filter(Column::SessionId.eq(session_id))
        .filter(Column::Kind.eq(ApprovalKind::User))
        .filter(Column::Status.eq(ApprovalRequestStatus::Pending))
        .one(db)
        .await?;
    Ok(row.filter(|row| username_eq_ci(&row.username, username)))
}

/// What [`upsert_request`] found on the question's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Advertised {
    /// A new question was put on the record — created, or reopened after one
    /// that ended unanswered. The one case worth announcing.
    Asked,
    /// A pending row was already there (possibly a concurrent asker's); its
    /// asker facts were refreshed and nothing else touched.
    AlreadyAsking,
    /// A decided row is in the way. Nothing was written: the answer stands
    /// for the asker to read back.
    DecisionStands,
    /// Asking again would need a ticket use that is no longer there. Nothing
    /// was written; the asker is turned away, not left waiting on a question
    /// nobody opened.
    TicketExhausted,
}

/// Refreshes a live question's asker facts — but never `started`: that is the
/// reap clock and the timeout anchor, and a client re-asking every few seconds
/// would otherwise push the window out indefinitely.
async fn try_refresh_pending(db: &DatabaseConnection, row: &ActiveModel) -> Result<bool, DbErr> {
    let refresh = ActiveModel {
        started: NotSet,
        status: NotSet,
        scope: NotSet,
        resolved_by_username: NotSet,
        resolved_by_user_id: NotSet,
        resolved_at: NotSet,
        consumed_at: NotSet,
        ..row.clone()
    };
    match Entity::update(refresh)
        .filter(Column::Status.eq(ApprovalRequestStatus::Pending))
        .exec(db)
        .await
    {
        Ok(_) => Ok(true),
        Err(DbErr::RecordNotUpdated) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Reopens a question that ended unanswered: the decision record is cleared and
/// the clock starts afresh, because this is a new asking — and a new asking
/// holds its own ticket use. The previous asking gave its use back when it
/// closed, so the spend comes first; if the reopen then loses to a concurrent
/// asker, the use is returned, mirroring how a decision that loses its
/// transition gives back what it took.
async fn try_reopen_unanswered(
    db: &DatabaseConnection,
    row: &ActiveModel,
) -> Result<Reopened, WarpgateError> {
    // The spend belongs to reopening, not to asking at all: a fresh question
    // is paid for by the use taken at authentication. Only when an unanswered
    // row is actually there to reopen is a new use taken — the probe can race,
    // but every losing arm below gives the spend back.
    let ticket_id = match &row.ticket_id {
        Set(id) => *id,
        _ => None,
    };
    if let Some(ticket_id) = ticket_id {
        let unanswered_row_exists = Entity::find()
            .filter(key_of(row)?.into_condition())
            .filter(Column::Status.is_in(ApprovalRequestStatus::UNANSWERED))
            .one(db)
            .await?
            .is_some();
        if !unanswered_row_exists {
            return Ok(Reopened::NotUnanswered);
        }
        match super::Ticket::spend_use(db, ticket_id).await {
            Ok(()) => {}
            Err(WarpgateError::InvalidTicket(_)) => return Ok(Reopened::TicketExhausted),
            Err(error) => return Err(error),
        }
    }

    let reopened = ActiveModel {
        status: Set(ApprovalRequestStatus::Pending),
        scope: Set(None),
        resolved_by_username: Set(None),
        resolved_by_user_id: Set(None),
        resolved_at: Set(None),
        consumed_at: Set(None),
        ..row.clone()
    };
    let result = match Entity::update(reopened)
        .filter(Column::Status.is_in(ApprovalRequestStatus::UNANSWERED))
        .exec(db)
        .await
    {
        Ok(_) => Ok(Reopened::Reopened),
        Err(DbErr::RecordNotUpdated) => Ok(Reopened::NotUnanswered),
        Err(error) => Err(error.into()),
    };
    if !matches!(result, Ok(Reopened::Reopened))
        && let Some(ticket_id) = ticket_id
        && let Err(error) = super::Ticket::refund_use(db, ticket_id).await
    {
        tracing::warn!(%error, %ticket_id, "Failed to refund the ticket of a reopen that lost");
    }
    result
}

/// The primary-key condition an advertiser's model names. The three key
/// columns are always `Set` — the model is built whole — so an unset one is a
/// caller bug worth surfacing, not defaulting.
fn key_of(row: &ActiveModel) -> Result<Key, WarpgateError> {
    match (&row.session_id, &row.kind, &row.target) {
        (Set(session_id), Set(kind), Set(target)) => Ok(Key::new(*session_id, *kind, target)),
        _ => Err(WarpgateError::InconsistentState(
            "approval request model without its key".into(),
        )),
    }
}

enum Reopened {
    Reopened,
    /// The row is no longer unanswered — decided, or a concurrent asker got
    /// there first. Whatever was spent above has been given back.
    NotUnanswered,
    TicketExhausted,
}

/// Publishes or re-advertises a single request, and says which it did — the
/// caller announces a question exactly when one was actually asked.
pub async fn upsert_request(
    db: &DatabaseConnection,
    row: ActiveModel,
) -> Result<Advertised, WarpgateError> {
    if try_refresh_pending(db, &row).await? {
        return Ok(Advertised::AlreadyAsking);
    }
    match try_reopen_unanswered(db, &row).await? {
        Reopened::Reopened => return Ok(Advertised::Asked),
        // Whether that is truly the end is decided below: a concurrent asker
        // that got the reopen in first has paid for a live question this
        // asker simply joins.
        Reopened::TicketExhausted => {
            return Ok(if try_refresh_pending(db, &row).await? {
                Advertised::AlreadyAsking
            } else {
                Advertised::TicketExhausted
            });
        }
        Reopened::NotUnanswered => {}
    }

    // A plain insert, not an ON CONFLICT one: what happened on a conflict is
    // the whole return value here, and no portable conflict action reports it
    // (a no-op update counts as a write on some backends and not others). The
    // violation is classified instead.
    //
    // The insert spends nothing: a fresh question is paid for by the use taken
    // when the session authenticated, which nothing has given back yet.
    match Entity::insert(row.clone()).exec(db).await {
        Ok(_) => Ok(Advertised::Asked),
        // Someone got a row in between the updates and the insert. Retry the
        // two updates so the answer is what actually happened, not a guess;
        // a decided row is the only thing neither can move.
        Err(error) if matches!(error.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) => {
            if try_refresh_pending(db, &row).await? {
                return Ok(Advertised::AlreadyAsking);
            }
            match try_reopen_unanswered(db, &row).await? {
                Reopened::Reopened => Ok(Advertised::Asked),
                Reopened::TicketExhausted => Ok(Advertised::TicketExhausted),
                Reopened::NotUnanswered => Ok(Advertised::DecisionStands),
            }
        }
        Err(error) => Err(error.into()),
    }
}

/// Ends one *asking* of a question, and settles the ticket use it holds: any
/// end but an approval gives the use back. `false` means this asking was no
/// longer pending — someone else settled it, and whoever did also settled the
/// ticket — so nothing was closed and nothing should be reported as having
/// been.
///
/// Every pending→terminal write goes through here, which is what makes the
/// refund rule unforgettable: there is no way to end an asking without
/// settling what it holds. The transition is pinned to the asking that was
/// read — key *and* `started`, which a reopen renews — so a close aimed at one
/// asking can neither end nor refund its successor.
async fn settle_asking(
    db: &DatabaseConnection,
    row: &Model,
    transition: StatusTransition,
) -> Result<bool, WarpgateError> {
    let keeps_the_spend = transition.to == ApprovalRequestStatus::Approved;
    let moved = transition
        .apply(
            db,
            Key::new(row.session_id, row.kind, &row.target)
                .into_condition()
                .add(Column::Started.eq(row.started)),
        )
        .await?;
    if moved > 0
        && !keeps_the_spend
        && let Some(ticket_id) = row.ticket_id
        && let Err(error) = super::Ticket::refund_use(db, ticket_id).await
    {
        tracing::warn!(%error, %ticket_id, "Failed to refund the ticket of an ended approval request");
    }
    Ok(moved > 0)
}

/// Ends a request as abandoned or timed out, and says whether it did — `false`
/// means the question was no longer pending, so nothing was closed and nothing
/// should be reported as having been.
pub async fn close_request(
    db: &DatabaseConnection,
    session_id: UserSessionId,
    kind: ApprovalKind,
    target: &str,
    status: UndecidedApprovalRequestStatus,
) -> Result<bool, WarpgateError> {
    let Some(row) = Entity::find()
        .filter(Key::new(session_id, kind, target).into_condition())
        .filter(Column::Status.eq(ApprovalRequestStatus::Pending))
        .one(db)
        .await?
    else {
        return Ok(false);
    };
    settle_asking(db, &row, StatusTransition::from_pending(status.into())).await
}

/// Writes a decision to a pending asking, and says whether it landed — `false`
/// when the asking was already settled, or was closed and asked afresh since
/// `row` was read (the pin in [`settle_asking`] tells the two askings apart).
///
/// An approval keeps the ticket spend — it transfers to the session being
/// admitted; a rejection gives it back like every other end.
pub async fn decide_asking(
    db: &DatabaseConnection,
    row: &Model,
    status: ApprovalRequestStatus,
    scope: Option<ApprovalScope>,
    resolved_by_username: Option<String>,
    resolved_by_user_id: Option<Uuid>,
) -> Result<bool, WarpgateError> {
    settle_asking(
        db,
        row,
        StatusTransition::from_pending(status)
            .set(Column::Scope, scope)
            .set(Column::ResolvedByUsername, resolved_by_username)
            .set(Column::ResolvedByUserId, resolved_by_user_id),
    )
    .await
}

/// mark a decision as acknowledged by its session
pub async fn mark_consumed(db: &DatabaseConnection, which: Key) -> Result<(), WarpgateError> {
    Entity::update_many()
        .col_expr(Column::ConsumedAt, OffsetDateTime::now_utc().into())
        .filter(which.into_condition())
        .filter(Column::ConsumedAt.is_null())
        .exec(db)
        .await?;
    Ok(())
}

/// Abandons everything a session was still asking, for when the session ends.
pub async fn abandon_requests_for_session(
    db: &DatabaseConnection,
    session_id: UserSessionId,
) -> Result<(), WarpgateError> {
    abandon_each(db, Column::SessionId.eq(session_id).into_condition()).await
}

/// Abandons every pending asking matching `which`, one at a time through
/// [`settle_asking`] so each settles its own ticket. Per-row rather than one
/// UPDATE because a refund belongs to exactly one won transition; the sweeps
/// this serves are small and human-paced.
async fn abandon_each(db: &DatabaseConnection, which: Condition) -> Result<(), WarpgateError> {
    let pending = Entity::find()
        .filter(which)
        .filter(Column::Status.eq(ApprovalRequestStatus::Pending))
        .all(db)
        .await?;
    for row in pending {
        settle_asking(
            db,
            &row,
            StatusTransition::from_pending(ApprovalRequestStatus::Abandoned),
        )
        .await?;
    }
    Ok(())
}

fn undelivered_user_decisions() -> Select<Entity> {
    Entity::find()
        .filter(Column::Kind.eq(ApprovalKind::User))
        .filter(Column::Status.is_in(ApprovalRequestStatus::DECIDED))
        .filter(Column::ConsumedAt.is_null())
}

pub async fn undelivered_user_approvals_for_node(
    db: &DatabaseConnection,
    node_id: NodeId,
) -> Result<Vec<Model>, WarpgateError> {
    Ok(undelivered_user_decisions()
        .filter(Column::NodeId.eq(node_id))
        .all(db)
        .await?)
}

pub async fn undelivered_user_approvals_for_session(
    db: &DatabaseConnection,
    session_id: UserSessionId,
) -> Result<Vec<Model>, WarpgateError> {
    Ok(undelivered_user_decisions()
        .filter(Column::SessionId.eq(session_id))
        .all(db)
        .await?)
}

pub async fn abandon_all_requested_before(
    db: &DatabaseConnection,
    cutoff: OffsetDateTime,
) -> Result<(), WarpgateError> {
    abandon_each(db, Column::Started.lt(cutoff).into_condition()).await
}

pub async fn delete_all_before(
    db: &DatabaseConnection,
    cutoff: OffsetDateTime,
) -> Result<(), WarpgateError> {
    let inactive = Column::Status
        .is_in(ApprovalRequestStatus::UNANSWERED)
        .or(Column::ConsumedAt.is_not_null());

    Entity::delete_many()
        .filter(Column::Started.lt(cutoff))
        .filter(inactive)
        .exec(db)
        .await?;
    Ok(())
}
