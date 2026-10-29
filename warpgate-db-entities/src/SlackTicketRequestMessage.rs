use sea_orm::entity::prelude::*;
use uuid::Uuid;
use warpgate_common::NodeId;

/// A Slack message advertising a pending ticket request, kept so that it can
/// be updated once the request is approved or denied
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "slack_ticket_request_messages")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub ticket_request_id: Uuid,
    /// the node that posted it and keeps it in sync
    pub node_id: NodeId,
    pub channel: String,
    pub ts: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
