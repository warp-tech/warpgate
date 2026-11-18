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
    /// `warpgate config apply`
    #[sea_orm(string_value = "Cli")]
    Cli,
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
    /// The provider takes ownership of a hand-made row. The resource sets
    /// `adopt_existing`.
    Adopt,
    Unchanged,
    /// A row with this name exists, and the provider doesn't own it
    Collision,
    /// The provider owns the row but may not make this change; `reason` says why
    Blocked,
    /// Gone from the source, but kept because the mass-deletion guard refused
    /// the prune. The only kind of error that a forced sync overrides.
    Guarded,
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

    /// Whether the change keeps the whole plan from being applied
    pub const fn is_error(self) -> bool {
        matches!(self, Self::Collision | Self::Blocked | Self::Guarded)
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

impl SyncPlan {
    /// Drops the unchanged resources. They are most of a plan and no part of
    /// a sync's outcome, so the history and the API responses omit them.
    #[must_use]
    pub fn changes_only(mut self) -> Self {
        self.0
            .retain(|change| change.action != PlanAction::Unchanged);
        self
    }

    pub fn unchanged(&self) -> usize {
        self.0
            .iter()
            .filter(|change| change.action == PlanAction::Unchanged)
            .count()
    }

    /// The plan's only errors come from the mass-deletion guard
    pub fn needs_force(&self) -> bool {
        let mut errors = self
            .0
            .iter()
            .map(|change| change.action)
            .filter(|action| action.is_error())
            .peekable();
        errors.peek().is_some() && errors.all(|action| action == PlanAction::Guarded)
    }

    pub fn stats(&self) -> PlanStats {
        let mut stats = PlanStats::default();
        for change in &self.0 {
            let count = match change.action {
                PlanAction::Create => &mut stats.create,
                PlanAction::Update => &mut stats.update,
                PlanAction::Adopt => &mut stats.adopt,
                PlanAction::Delete => &mut stats.delete,
                PlanAction::Collision => &mut stats.collision,
                PlanAction::Blocked => &mut stats.blocked,
                PlanAction::Guarded => &mut stats.guarded,
                PlanAction::WouldPrune => &mut stats.would_prune,
                PlanAction::Unchanged => continue,
            };
            *count += 1;
        }
        stats
    }
}

/// How many resources of a plan fall under each [`PlanAction`]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Object)]
pub struct PlanStats {
    pub create: u32,
    pub update: u32,
    pub adopt: u32,
    pub delete: u32,
    pub collision: u32,
    pub blocked: u32,
    pub guarded: u32,
    pub would_prune: u32,
}

/// One outcome of syncing a provider. A later sync with the same unchanged or
/// failed outcome moves `checked_at` instead of adding a row. A row therefore
/// covers the time from `started_at` through `checked_at`.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "provider_syncs")]
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
    /// Entries as in `warpgate config plan --format json`, without the
    /// unchanged resources
    #[sea_orm(column_type = "Json", nullable)]
    pub plan: Option<SyncPlan>,
    #[sea_orm(column_type = "Text", nullable)]
    pub error: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

#[cfg(test)]
mod tests {
    use super::PlanAction::{Blocked, Create, Guarded, WouldPrune};
    use super::*;

    #[test]
    fn only_the_guard_alone_needs_force() {
        let plan = |actions: &[PlanAction]| {
            SyncPlan(
                actions
                    .iter()
                    .map(|action| PlannedChange {
                        kind: "Role".into(),
                        name: "dba".into(),
                        action: *action,
                        fields: vec![],
                        reason: None,
                    })
                    .collect(),
            )
        };
        assert!(plan(&[Create, Guarded, Guarded]).needs_force());
        assert!(!plan(&[Guarded, Blocked]).needs_force());
        assert!(!plan(&[Create, WouldPrune]).needs_force());
        assert!(!plan(&[]).needs_force());
    }
}
