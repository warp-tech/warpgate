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
/// credential becomes needed, and it is deleted when the approval is resolved
/// (locally or via the internal cluster RPC to the owner), when the waiter
/// gives up, or by age-based reaping if the owner died.
///
/// The in-memory auth state on `node_id` remains the authority on the
/// authentication itself; this row only advertises the request cluster-wide
/// and names the node to deliver the decision to.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "session_approval_requests")]
pub struct Model {
    /// The auth-state id on the owning node.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub kind: ApprovalRequestKind,
    pub session_id: Uuid,
    /// The node whose in-memory store owns the auth state (the row's creator).
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
