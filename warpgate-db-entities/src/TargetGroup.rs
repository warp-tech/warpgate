use poem_openapi::{Enum, Object};
use sea_orm::entity::prelude::*;
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, PartialEq, Eq, Serialize, Clone, Enum, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum BootstrapThemeColor {
    #[sea_orm(string_value = "primary")]
    Primary,
    #[sea_orm(string_value = "secondary")]
    Secondary,
    #[sea_orm(string_value = "success")]
    Success,
    #[sea_orm(string_value = "danger")]
    Danger,
    #[sea_orm(string_value = "warning")]
    Warning,
    #[sea_orm(string_value = "info")]
    Info,
    #[sea_orm(string_value = "light")]
    Light,
    #[sea_orm(string_value = "dark")]
    Dark,
}

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "target_groups")]
#[oai(rename = "TargetGroup")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub name: String,
    #[sea_orm(column_type = "Text")]
    pub description: String,
    pub color: Option<BootstrapThemeColor>, // Bootstrap theme color for UI display
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::Target::Entity")]
    Target,
}

impl ActiveModelBehavior for ActiveModel {}
