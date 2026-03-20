use chrono::{DateTime, Utc};
use poem_openapi::{Enum, Object};
use sea_orm::entity::prelude::*;
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, PartialEq, Eq, Serialize, Clone, Enum, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
#[oai(rename = "TicketRequestStatus")]
pub enum TicketRequestStatus {
    #[sea_orm(string_value = "pending")]
    Pending,
    #[sea_orm(string_value = "approved")]
    Approved,
    #[sea_orm(string_value = "denied")]
    Denied,
    #[sea_orm(string_value = "expired")]
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "ticket_requests")]
#[oai(rename = "TicketRequest")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub user_id: Uuid,
    pub username: String,
    pub target_name: String,
    pub requested_duration_seconds: Option<i64>,
    pub requested_uses: Option<i16>,
    #[sea_orm(column_type = "Text")]
    pub description: String,
    pub status: TicketRequestStatus,
    pub resolved_by_username: Option<String>,
    pub ticket_id: Option<Uuid>,
    pub created: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    #[sea_orm(column_type = "Text", nullable)]
    pub deny_reason: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::User::Entity",
        from = "Column::UserId",
        to = "super::User::Column::Id"
    )]
    User,
    #[sea_orm(
        belongs_to = "super::Ticket::Entity",
        from = "Column::TicketId",
        to = "super::Ticket::Column::Id"
    )]
    Ticket,
}

impl Related<super::User::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl Related<super::Ticket::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Ticket.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
