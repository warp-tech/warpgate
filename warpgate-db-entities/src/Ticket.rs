use chrono::{DateTime, Utc};
use poem_openapi::Object;
use sea_orm::entity::prelude::*;
use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "tickets")]
#[oai(rename = "Ticket")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    #[oai(skip)]
    pub secret: String,
    pub username: String,
    pub target: String,
    pub uses_left: Option<u32>,
    pub expiry: Option<DateTime<Utc>>,
    pub created: DateTime<Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::Session::Entity")]
    Sessions,
}

impl ActiveModelBehavior for ActiveModel {}
