use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "http_sessions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub expires: Option<OffsetDateTime>,
    #[sea_orm(column_type = "Text")]
    pub data: String,
    pub updated: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
