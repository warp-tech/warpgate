use poem_openapi::{Enum, NewType, Object};
use sea_orm::FromJsonQueryResult;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Enum)]
#[serde(rename_all = "snake_case")]
#[oai(rename_all = "snake_case")]
pub enum PlanAction {
    Create,
    Update,
    /// Takes over a row created by hand; the resource has the adopt annotation
    Adopt,
    Unchanged,
    /// A row with this name exists, and the provider doesn't own it
    Collision,
    /// The provider owns the row but may not make this change; `reason` says why
    Blocked,
    /// Gone from the source, but kept because pruning is off
    WouldPrune,
    Delete,
}

impl PlanAction {
    /// Whether applying the plan writes this change
    pub const fn is_pending(self) -> bool {
        matches!(
            self,
            Self::Create | Self::Update | Self::Adopt | Self::Delete
        )
    }
}

/// A changed field of a resource
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Object)]
pub struct PlannedField {
    /// Where in the resource, e.g. `spec.options.ssh.port`
    pub path: String,
    /// Set for a credential. Its values are never in a plan, so `from` and
    /// `to` are absent.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub credential: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<Value>,
}

/// One resource in a plan
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Object)]
pub struct PlannedChange {
    pub kind: String,
    pub name: String,
    pub action: PlanAction,
    /// For an update or adoption
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<PlannedField>,
    /// For a collision or a blocked change
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A sync's plan, one entry per resource
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, NewType, FromJsonQueryResult)]
#[serde(transparent)]
#[oai(from_parameter = false, from_multipart = false, to_header = false)]
pub struct SyncPlan(pub Vec<PlannedChange>);

/// One outcome of syncing a provider. A later sync with the same unchanged or
/// failed outcome moves `checked_at` instead of adding a row. A row therefore
/// covers the time from `started_at` through `checked_at`.
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
    /// Same JSON as `warpgate config plan --format json`
    #[sea_orm(column_type = "Json", nullable)]
    pub plan: Option<SyncPlan>,
    #[sea_orm(column_type = "Text", nullable)]
    pub error: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
