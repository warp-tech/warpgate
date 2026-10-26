use sea_orm::entity::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::{NodeId, UserSessionId};

/// A Slack message advertising an admin approval request, kept so that it can
/// be updated once the request is settled
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "slack_approval_messages")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub session_id: UserSessionId,
    pub target: String,
    /// `started` of the request when it was posted: a reopened request is a
    /// new question and gets new messages
    pub request_started: OffsetDateTime,
    /// the node that posted it and keeps it in sync
    pub node_id: NodeId,
    pub channel: String,
    pub ts: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
