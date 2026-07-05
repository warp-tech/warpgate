use poem_openapi::{Enum, Object};
use sea_orm::entity::prelude::*;
use sea_orm::sea_query::ForeignKeyAction;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, Enum, DeriveActiveEnum, Serialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum RecordingKind {
    #[sea_orm(string_value = "terminal")]
    Terminal,
    #[sea_orm(string_value = "traffic")]
    Traffic,
    #[sea_orm(string_value = "kubernetes")]
    Kubernetes,
    #[sea_orm(string_value = "desktop")]
    Desktop,
}

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "recordings")]
#[oai(rename = "Recording")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub name: String,
    pub started: OffsetDateTime,
    pub ended: Option<OffsetDateTime>,
    pub session_id: Uuid,
    pub kind: RecordingKind,
    #[sea_orm(column_type = "Text")]
    pub metadata: String,
    /// Storage layout: 1 = single legacy file, 2 = folder (`data.ndjson` [+ desktop
    /// `index.json`]). Defaults to 1 for rows created before the folder layout.
    #[sea_orm(default_value = 1)]
    pub generation: i32,
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {
    Session,
}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        match self {
            Self::Session => Entity::belongs_to(super::Session::Entity)
                .from(Column::SessionId)
                .to(super::Session::Column::Id)
                .on_delete(ForeignKeyAction::Cascade)
                .into(),
        }
    }
}

impl Related<super::Session::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Session.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
