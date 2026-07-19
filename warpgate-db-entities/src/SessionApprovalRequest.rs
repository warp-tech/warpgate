use sea_orm::entity::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::auth::ApprovalKind;

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

/// A pending out-of-band approval request — a first-class record, not a
/// projection: the wait site on the owning node creates it when an approval
/// becomes needed, and it is deleted when the approval is resolved (locally or
/// via the internal cluster RPC to the owner), when the waiter gives up, or by
/// age-based reaping if the owner died.
///
/// Keyed by `(session_id, kind)`: a session waits on at most one approval of
/// each kind at a time, which makes creation idempotent — a wait site that runs
/// twice upserts the same row instead of queueing a duplicate.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "session_approval_requests")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub session_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub kind: ApprovalRequestKind,
    /// The auth state this request resolves against, for [`ApprovalRequestKind::User`].
    /// Admin approval is a gate on the connection rather than a credential, so
    /// its rows carry no auth state.
    pub auth_state_id: Option<Uuid>,
    /// The node running the session that is waiting (the row's creator).
    pub node_id: Uuid,
    pub protocol: String,
    pub username: String,
    pub target: String,
    pub remote_address: Option<String>,
    pub identification_string: String,
    pub started: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
