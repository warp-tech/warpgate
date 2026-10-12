use std::collections::HashMap;

use poem_openapi::{Enum, Object};
use sea_orm::entity::prelude::*;
use sea_orm::sea_query::Func;
use sea_orm::QueryOrder;
use serde::Serialize;
use uuid::Uuid;
use warpgate_common::fuzzy::fuzzy_rank;
use warpgate_common::{Target, TargetOptions};

use crate::TargetGroup;

#[derive(Debug, PartialEq, Eq, Serialize, Clone, Copy, Enum, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum TargetKind {
    #[sea_orm(string_value = "http")]
    Http,
    #[sea_orm(string_value = "kubernetes")]
    Kubernetes,
    #[sea_orm(string_value = "mysql")]
    MySql,
    #[sea_orm(string_value = "ssh")]
    Ssh,
    #[sea_orm(string_value = "postgres")]
    Postgres,
    #[sea_orm(string_value = "vnc")]
    Vnc,
    #[sea_orm(string_value = "rdp")]
    Rdp,
}

impl From<&TargetOptions> for TargetKind {
    fn from(options: &TargetOptions) -> Self {
        match options {
            TargetOptions::Http(_) => Self::Http,
            TargetOptions::Kubernetes(_) => Self::Kubernetes,
            TargetOptions::MySql(_) => Self::MySql,
            TargetOptions::Postgres(_) => Self::Postgres,
            TargetOptions::Ssh(_) => Self::Ssh,
            TargetOptions::Vnc(_) => Self::Vnc,
            TargetOptions::Rdp(_) => Self::Rdp,
        }
    }
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
    pub ticket_max_duration_seconds: Option<i64>,
    pub ticket_requests_disabled: bool,
    pub ticket_require_approval: bool,
    pub ticket_max_uses: Option<i16>,
    pub require_approval: bool,
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

impl Entity {
    /// Targets left-joined with their group, in the order target lists are
    /// shown: grouped targets first, then by group name, then by target name.
    /// Combine with [`Select::select_also`] to also load the group.
    pub fn find_grouped() -> Select<Self> {
        Self::find()
            .left_join(super::TargetGroup::Entity)
            .order_by_asc(Expr::col((Self, Column::GroupId)).is_null())
            .order_by_asc(Expr::expr(Func::lower(Expr::col((
                super::TargetGroup::Entity,
                super::TargetGroup::Column::Name,
            )))))
            .order_by_asc(Expr::expr(Func::lower(Expr::col((Self, Column::Name)))))
            .order_by_asc(Column::Id)
    }
}

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
            ticket_max_duration_seconds: model.ticket_max_duration_seconds,
            ticket_requests_disabled: model.ticket_requests_disabled,
            ticket_require_approval: model.ticket_require_approval,
            ticket_max_uses: model.ticket_max_uses,
            require_approval: model.require_approval,
        })
    }
}

pub fn fuzzy_filter_targets<'a, M>(
    targets: &'a [M],
    groups: &'a [TargetGroup::Model],
    query: &str,
) -> Vec<&'a M>
where
    Target: TryFrom<M>,
    M: Clone,
{
    let targets: Vec<(&M, Target)> = targets
        .iter()
        .filter_map(|x| x.clone().try_into().ok().map(|t| (x, t)))
        .collect::<Vec<_>>();
    let group_map: HashMap<Uuid, &TargetGroup::Model> = groups.iter().map(|g| (g.id, g)).collect();
    fuzzy_rank(&targets, query, |(_, t)| {
        let group = t.group_id.and_then(|group_id| group_map.get(&group_id));
        [
            t.name.as_str(),
            t.description.as_str(),
            group.map(|g| g.name.as_str()).unwrap_or_default(),
        ]
    })
    .iter()
    .map(|x| x.0)
    .collect()
}

/// Like [`fuzzy_filter_targets`], but with each group's targets pulled together,
/// for lists that group targets by adjacency. Groups, and the ungrouped targets,
/// are ordered by their best match.
pub fn fuzzy_filter_targets_grouped<'a>(
    targets: &'a [Model],
    groups: &'a [TargetGroup::Model],
    query: &str,
) -> Vec<&'a Model> {
    let mut by_group: Vec<(Option<Uuid>, Vec<&Model>)> = vec![];
    for target in fuzzy_filter_targets(targets, groups, query) {
        match by_group.iter_mut().find(|(id, _)| *id == target.group_id) {
            Some((_, members)) => members.push(target),
            None => by_group.push((target.group_id, vec![target])),
        }
    }
    by_group.into_iter().flat_map(|(_, members)| members).collect()
}
