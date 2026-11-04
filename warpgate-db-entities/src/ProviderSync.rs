use poem_openapi::{Enum, Object};
use sea_orm::entity::prelude::*;
use sea_orm::query::JsonValue;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::ProviderId;

#[derive(Debug, PartialEq, Eq, Serialize, Clone, Copy, Enum, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum SyncTrigger {
    #[sea_orm(string_value = "Startup")]
    Startup,
    #[sea_orm(string_value = "Interval")]
    Interval,
    #[sea_orm(string_value = "Api")]
    Api,
    #[sea_orm(string_value = "Webhook")]
    Webhook,
}

#[derive(Debug, PartialEq, Eq, Serialize, Clone, Copy, Enum, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum SyncStatus {
    #[sea_orm(string_value = "Applied")]
    Applied,
    #[sea_orm(string_value = "Unchanged")]
    Unchanged,
    #[sea_orm(string_value = "Failed")]
    Failed,
}

/// One outcome of syncing a provider. A later sync that reaches the same
/// unchanged or failed outcome moves `checked_at` instead of adding a row, so
/// a row reads "in this state from `started_at` through `checked_at`".
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "provider_syncs")]
#[oai(rename = "ProviderSync")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub provider: ProviderId,
    pub triggered_by: SyncTrigger,
    pub status: SyncStatus,
    pub started_at: OffsetDateTime,
    pub checked_at: OffsetDateTime,
    /// Where the files came from, without credentials
    #[sea_orm(column_type = "Text")]
    pub source: String,
    /// The commit, or a hash of a directory's files
    #[sea_orm(column_type = "Text", nullable)]
    pub revision: Option<String>,
    /// The plan, as `warpgate config plan --format json` prints it
    #[sea_orm(column_type = "Json", nullable)]
    pub plan: Option<JsonValue>,
    #[sea_orm(column_type = "Text", nullable)]
    pub error: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
