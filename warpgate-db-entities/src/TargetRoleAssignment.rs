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
    /// Allow file uploads via SCP/SFTP
    #[sea_orm(default_value = true)]
    pub allow_file_upload: bool,
    /// Allow file downloads via SCP/SFTP
    #[sea_orm(default_value = true)]
    pub allow_file_download: bool,
    /// Allowed paths (JSON array of path patterns, null = all paths allowed)
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub allowed_paths: Option<serde_json::Value>,
    /// Blocked file extensions (JSON array, null = no extensions blocked)
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub blocked_extensions: Option<serde_json::Value>,
    /// Maximum file size in bytes (null = no limit)
    pub max_file_size: Option<i64>,
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
