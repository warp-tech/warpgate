use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "sessions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub target_snapshot: Option<String>,
    pub username: Option<String>,
    pub remote_address: String,
    pub started: DateTime<Utc>,
    pub ended: Option<DateTime<Utc>>,
    pub ticket_id: Option<Uuid>,
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {
    Recordings,
    Ticket,
}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        match self {
            Self::Recordings => Entity::has_many(super::Recording::Entity)
                .from(Column::Id)
                .to(super::Recording::Column::SessionId)
                .into(),
            Self::Ticket => Entity::belongs_to(super::Ticket::Entity)
                .from(Column::TicketId)
                .to(super::Ticket::Column::Id)
                .into(),
        }
    }
}

impl Related<super::Ticket::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Ticket.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
