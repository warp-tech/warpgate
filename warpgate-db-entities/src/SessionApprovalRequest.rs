use std::ops::Deref;

use sea_orm::entity::prelude::*;
use sea_orm::sea_query::{IntoCondition, OnConflict, SimpleExpr};
use sea_orm::{Condition, QueryFilter, Set};
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
    /// hashed credential set, part of the key of the "remember" decisions
    pub credentials_digest: Option<String>,
    /// ticket to consume if this request is approved (if consumption is deferred (HTTP))
    pub consumes_ticket_id: Option<Uuid>,
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
        Self::CredentialsDigest,
        Self::ConsumesTicketId,
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
pub struct StatusTransition {
    to: ApprovalRequestStatus,
    /// a filter on start condition
    from: Condition,
    /// columns to write
    columns: Vec<(Column, SimpleExpr)>,
}

impl StatusTransition {
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

    /// returns change count
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

/// Condition guaranteed to key on primary key
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

/// publish or readvertise a single request
pub async fn upsert_request(
    db: &DatabaseConnection,
    row: ActiveModel,
) -> Result<(), WarpgateError> {
    let same_pending = ActiveModel {
        status: Set(ApprovalRequestStatus::Pending),
        ..row.clone()
    };

    match Entity::update(same_pending)
        .filter(Column::Status.is_not_in(ApprovalRequestStatus::DECIDED))
        .exec(db)
        .await
    {
        // Found an existing reusable request and updated it
        Ok(_) => return Ok(()),
        // Nothing usable found, continue
        Err(DbErr::RecordNotUpdated) => {}
        Err(error) => return Err(error.into()),
    }

    // No entry ot entry was undecided
    match Entity::insert(row)
        .on_conflict(
            OnConflict::columns([Column::SessionId, Column::Kind, Column::Target])
                // .do_nothing() is broken in sea-orm on MySQL
                // this is a portable "do nothing" (noop update):
                .update_column(Column::SessionId)
                .to_owned(),
        )
        .exec(db)
        .await
    {
        Ok(_) => Ok(()),
        Err(DbErr::RecordNotInserted) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// ends a request without as abandoned or timed out
///
/// not for final decisions - this does not cross check start timestamp
pub async fn close_request(
    db: &DatabaseConnection,
    session_id: UserSessionId,
    kind: ApprovalKind,
    target: &str,
    status: UndecidedApprovalRequestStatus,
) -> Result<(), WarpgateError> {
    StatusTransition::from_pending(status.into())
        .apply(db, Key::new(session_id, kind, target).clone())
        .await?;
    Ok(())
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

/// batch mark all session's requests as abandoned
pub async fn abandon_requests_for_session(
    db: &DatabaseConnection,
    session_id: UserSessionId,
) -> Result<(), WarpgateError> {
    StatusTransition::from_pending(ApprovalRequestStatus::Abandoned)
        .apply(db, Column::SessionId.eq(session_id).into_condition())
        .await?;
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
    StatusTransition::from_pending(ApprovalRequestStatus::Abandoned)
        .apply(db, Column::Started.lt(cutoff).into_condition())
        .await?;
    Ok(())
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
