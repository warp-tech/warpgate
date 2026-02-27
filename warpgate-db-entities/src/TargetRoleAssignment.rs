use poem_openapi::Object;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize, Object)]
#[sea_orm(table_name = "target_roles")]
#[oai(rename = "TargetRoleAssignment")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i32,
    pub target_id: Uuid,
    pub role_id: Uuid,
    /// Allow file uploads via SFTP (null = inherit from role)
    pub allow_file_upload: Option<bool>,
    /// Allow file downloads via SFTP (null = inherit from role)
    pub allow_file_download: Option<bool>,
    /// Allowed paths (JSON array of path patterns, null = inherit from role)
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub allowed_paths: Option<serde_json::Value>,
    /// Blocked file extensions (JSON array, null = inherit from role)
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub blocked_extensions: Option<serde_json::Value>,
    /// Maximum file size in bytes (null = inherit from role)
    pub max_file_size: Option<i64>,
    /// File transfer only mode (null = inherit from role, true/false = override)
    pub file_transfer_only: Option<bool>,
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {
    Target,
    Role,
}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        match self {
            Self::Target => Entity::belongs_to(super::Target::Entity)
                .from(Column::TargetId)
                .to(super::Target::Column::Id)
                .into(),
            Self::Role => Entity::belongs_to(super::Role::Entity)
                .from(Column::RoleId)
                .to(super::Role::Column::Id)
                .into(),
        }
    }
}

impl ActiveModelBehavior for ActiveModel {}
