use poem_openapi::{Enum, Object};
use sea_orm::entity::prelude::*;
use serde::Serialize;
use uuid::Uuid;
use warpgate_common::{Target, TargetOptions};

#[derive(Debug, PartialEq, Eq, Serialize, Clone, Enum, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum TargetKind {
    #[sea_orm(string_value = "http")]
    Http,
    #[sea_orm(string_value = "mysql")]
    MySql,
    #[sea_orm(string_value = "ssh")]
    Ssh,
    #[sea_orm(string_value = "postgres")]
    Postgres,
    #[sea_orm(string_value = "web_admin")]
    WebAdmin,
}

impl From<&TargetOptions> for TargetKind {
    fn from(options: &TargetOptions) -> Self {
        match options {
            TargetOptions::Http(_) => Self::Http,
            TargetOptions::MySql(_) => Self::MySql,
            TargetOptions::Postgres(_) => Self::Postgres,
            TargetOptions::Ssh(_) => Self::Ssh,
            TargetOptions::WebAdmin(_) => Self::WebAdmin,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Clone, Enum, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum SshAuthKind {
    #[sea_orm(string_value = "password")]
    Password,
    #[sea_orm(string_value = "publickey")]
    PublicKey,
}

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "targets")]
#[oai(rename = "Target")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub name: String,
    #[sea_orm(column_type = "Text")]
    pub description: String,
    pub kind: TargetKind,
    pub options: serde_json::Value,
    pub rate_limit_bytes_per_second: Option<i64>,
    pub group_id: Option<Uuid>,
}

impl Related<super::Role::Entity> for Entity {
    fn to() -> RelationDef {
        super::TargetRoleAssignment::Relation::Role.def()
    }

    fn via() -> Option<RelationDef> {
        Some(super::TargetRoleAssignment::Relation::Target.def().rev())
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::TargetGroup::Entity",
        from = "Column::GroupId",
        to = "super::TargetGroup::Column::Id"
    )]
    TargetGroup,
}

impl Related<super::TargetGroup::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::TargetGroup.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl TryFrom<Model> for Target {
    type Error = serde_json::Error;

    fn try_from(model: Model) -> Result<Self, Self::Error> {
        let options: TargetOptions = serde_json::from_value(model.options)?;
        Ok(Self {
            id: model.id,
            name: model.name,
            description: model.description,
            allow_roles: vec![],
            options,
            rate_limit_bytes_per_second: model.rate_limit_bytes_per_second.map(|v| v as u32),
            group_id: model.group_id,
        })
    }
}
