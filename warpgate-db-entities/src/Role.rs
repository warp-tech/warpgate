use poem_openapi::Object;
use sea_orm::entity::prelude::*;
use serde::Serialize;
use uuid::Uuid;
use warpgate_common::Role;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "roles")]
#[oai(rename = "Role")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub name: String,
    #[sea_orm(column_type = "Text")]
    pub description: String,
    // File transfer defaults for this role
    /// Allow file uploads by default for targets with this role
    #[sea_orm(default_value = true)]
    pub allow_file_upload: bool,
    /// Allow file downloads by default for targets with this role
    #[sea_orm(default_value = true)]
    pub allow_file_download: bool,
    /// Default allowed paths (JSON array of path patterns, null = all paths allowed)
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub allowed_paths: Option<serde_json::Value>,
    /// Default blocked file extensions (JSON array, null = no extensions blocked)
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub blocked_extensions: Option<serde_json::Value>,
    /// Default maximum file size in bytes (null = no limit)
    pub max_file_size: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl Related<super::Target::Entity> for Entity {
    fn to() -> RelationDef {
        super::TargetRoleAssignment::Relation::Target.def()
    }

    fn via() -> Option<RelationDef> {
        Some(super::TargetRoleAssignment::Relation::Role.def().rev())
    }
}

impl Related<super::User::Entity> for Entity {
    fn to() -> RelationDef {
        super::UserRoleAssignment::Relation::User.def()
    }

    fn via() -> Option<RelationDef> {
        Some(super::UserRoleAssignment::Relation::Role.def().rev())
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for Role {
    fn from(model: Model) -> Self {
        Self {
            id: model.id,
            name: model.name,
            description: model.description,
            allow_file_upload: model.allow_file_upload,
            allow_file_download: model.allow_file_download,
            allowed_paths: model
                .allowed_paths
                .and_then(|v| serde_json::from_value(v).ok()),
            blocked_extensions: model
                .blocked_extensions
                .and_then(|v| serde_json::from_value(v).ok()),
            max_file_size: model.max_file_size,
        }
    }
}
