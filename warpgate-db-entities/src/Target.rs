use poem_openapi::{Enum, Object};
use sea_orm::entity::prelude::*;
use serde::Serialize;
use uuid::Uuid;
use warpgate_common::{Target, TargetOptions};

#[derive(Debug, PartialEq, Eq, Serialize, Clone, Enum, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(Some(16))")]
pub enum TargetKind {
    #[sea_orm(string_value = "http")]
    Http,
    #[sea_orm(string_value = "mysql")]
    MySql,
    #[sea_orm(string_value = "ssh")]
    Ssh,
    #[sea_orm(string_value = "web_admin")]
    WebAdmin,
}

#[derive(Debug, PartialEq, Eq, Serialize, Clone, Enum, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(Some(16))")]
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
    pub kind: TargetKind,
    pub options: serde_json::Value,
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
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl TryFrom<Model> for Target {
    type Error = serde_json::Error;

    fn try_from(model: Model) -> Result<Self, Self::Error> {
        let options: TargetOptions = serde_json::from_value(model.options)?;
        Ok(Self {
            name: model.name,
            allow_roles: vec![],
            options,
        })
    }
}
