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
    pub match_digest: Option<String>,
    /// the spent ticket used for this session (for refund)
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

pub enum RequestAsk {
    Admin { ticket_id: Option<Uuid> },
    User { identification_string: String },
}

impl RequestAsk {
    pub const fn kind(&self) -> ApprovalKind {
        match self {
            Self::Admin { .. } => ApprovalKind::Admin,
            Self::User { .. } => ApprovalKind::User,
        }
    }

    const fn ticket_id(&self) -> Option<Uuid> {
        match self {
            Self::Admin { ticket_id } => *ticket_id,
            Self::User { .. } => None,
        }
    }
}

pub struct NewRequest {
    pub session_id: UserSessionId,
    pub target: String,
    pub node_id: NodeId,
    pub protocol: String,
    pub username: String,
    pub user_id: Uuid,
    pub remote_address: Option<String>,
    pub match_digest: Option<String>,
    pub started: OffsetDateTime,
    pub about: RequestAsk,
}

impl NewRequest {
    #[must_use]
    pub fn key(&self) -> Key {
        Key::new(self.session_id, self.about.kind(), &self.target)
    }
}

impl From<NewRequest> for ActiveModel {
    fn from(request: NewRequest) -> Self {
        let (identification_string, ticket_id) = match &request.about {
            RequestAsk::Admin { ticket_id } => (None, *ticket_id),
            RequestAsk::User {
                identification_string,
            } => (Some(identification_string.clone()), None),
        };
        Self {
            session_id: Set(request.session_id),
            kind: Set(request.about.kind()),
            node_id: Set(request.node_id),
            protocol: Set(request.protocol),
            username: Set(request.username),
            user_id: Set(request.user_id),
            target: Set(request.target),
            remote_address: Set(request.remote_address),
            identification_string: Set(identification_string),
            match_digest: Set(request.match_digest),
            ticket_id: Set(ticket_id),
            started: Set(request.started),
            // Not the asker's to state: a question is asked unanswered.
            status: Set(ApprovalRequestStatus::Pending),
            scope: Set(None),
            resolved_by_username: Set(None),
            resolved_by_user_id: Set(None),
            resolved_at: Set(None),
            consumed_at: Set(None),
        }
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

/// Refreshes a live request's facts
async fn try_refresh_pending(db: &DatabaseConnection, row: &ActiveModel) -> Result<bool, DbErr> {
    let refresh = ActiveModel {
        started: NotSet, // not touching this
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

enum Reopened {
    Reopened,
    /// The entry to be reopened just got refreshed by someone else
    NotUnanswered,
    TicketExhausted,
}

/// Reopen a matching old request (spends the ticket again)
async fn try_reopen_unanswered(
    db: &DatabaseConnection,
    key: &Key,
    ticket_id: Option<Uuid>,
    row: &ActiveModel,
) -> Result<Reopened, WarpgateError> {
    if let Some(ticket_id) = ticket_id {
        let unanswered_row_exists = Entity::find()
            .filter(key.clone().into_condition())
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

/// Result of an upsert_request
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Advertised {
    /// Created or reopened an entry
    Asked,
    /// Refreshed an already existing pending entry
    AlreadyAsking,
    /// There is already a matching entry with a decision
    DecisionStands,
    /// The ticket used for the request is already exhausted
    /// nobody opened.
    TicketExhausted,
}

/// Create or re-advertise a request
pub async fn upsert_request(
    db: &DatabaseConnection,
    request: NewRequest,
) -> Result<Advertised, WarpgateError> {
    let key = request.key();
    let ticket_id = request.about.ticket_id();
    let row = ActiveModel::from(request);

    if try_refresh_pending(db, &row).await? {
        return Ok(Advertised::AlreadyAsking);
    }
    match try_reopen_unanswered(db, &key, ticket_id, &row).await? {
        Reopened::Reopened => return Ok(Advertised::Asked),
        Reopened::TicketExhausted => {
            return Ok(if try_refresh_pending(db, &row).await? {
                // The other requester has already spent a ticket so it's fine
                Advertised::AlreadyAsking
            } else {
                Advertised::TicketExhausted
            });
        }
        Reopened::NotUnanswered => {}
    }

    match Entity::insert(row.clone()).exec(db).await {
        Ok(_) => Ok(Advertised::Asked),
        Err(error) if matches!(error.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) => {
            // raced, try refreshing again
            if try_refresh_pending(db, &row).await? {
                return Ok(Advertised::AlreadyAsking);
            }
            match try_reopen_unanswered(db, &key, ticket_id, &row).await? {
                Reopened::Reopened => Ok(Advertised::Asked),
                Reopened::TicketExhausted => Ok(Advertised::TicketExhausted),
                Reopened::NotUnanswered => Ok(Advertised::DecisionStands),
            }
        }
        Err(error) => Err(error.into()),
    }
}

// Returns whether the change succeeded, or was raced by somebody else
async fn settle_request_internal(
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
    // false if the request was already settled
    Ok(moved > 0)
}

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
    settle_request_internal(db, &row, StatusTransition::from_pending(status.into())).await
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApprovalActor {
    /// None if not a user (admin API token)
    pub username: Option<String>,
    pub user_id: Uuid,
}

pub async fn settle_request(
    db: &DatabaseConnection,
    row: &Model,
    status: ApprovalRequestStatus,
    scope: Option<ApprovalScope>,
    resolved_by: &ApprovalActor,
) -> Result<bool, WarpgateError> {
    settle_request_internal(
        db,
        row,
        StatusTransition::from_pending(status)
            .set(Column::Scope, scope)
            .set(Column::ResolvedByUsername, resolved_by.username.clone())
            .set(Column::ResolvedByUserId, resolved_by.user_id),
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

pub async fn abandon_requests_for_session(
    db: &DatabaseConnection,
    session_id: UserSessionId,
) -> Result<(), WarpgateError> {
    abandon_each(db, Column::SessionId.eq(session_id).into_condition()).await
}

async fn abandon_each(db: &DatabaseConnection, which: Condition) -> Result<(), WarpgateError> {
    let pending = Entity::find()
        .filter(which)
        .filter(Column::Status.eq(ApprovalRequestStatus::Pending))
        .all(db)
        .await?;
    for row in pending {
        settle_request_internal(
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

/// One session's undelivered decisions, `node_id`-scoped like the sweep:
/// a row's `node_id` is the node holding the auth state it must be delivered
/// to, and only that node may conclude "the state is gone" — anywhere else,
/// absence from the local store means nothing.
pub async fn undelivered_user_approvals_for_session(
    db: &DatabaseConnection,
    node_id: NodeId,
    session_id: UserSessionId,
) -> Result<Vec<Model>, WarpgateError> {
    Ok(undelivered_user_decisions()
        .filter(Column::NodeId.eq(node_id))
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
