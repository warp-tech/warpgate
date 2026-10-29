use std::collections::HashMap;

use sea_orm::{ConnectionTrait, EntityTrait};
use uuid::Uuid;
use warpgate_common::{
    MaybeSecretRef, StoredSecret, Target as TargetConfig, TargetSecrets, WarpgateError,
};
use warpgate_db_entities::{Role, Target, TargetGroup, TargetRoleAssignment};
use warpgate_gitops::plan::{Current, Row};
use warpgate_gitops::types::{RoleSpec, TargetGroupSpec, TargetSpec};

/// The rows a plan is computed against, with references by name. Inline
/// credentials come back decrypted so they compare with a file's literals:
/// the result must not be logged.
pub async fn load_current<C: ConnectionTrait>(db: &C) -> Result<Current, WarpgateError> {
    let groups = TargetGroup::Entity::find().all(db).await?;
    let roles = Role::Entity::find().all(db).await?;
    let group_names: HashMap<Uuid, &str> = groups.iter().map(|g| (g.id, g.name.as_str())).collect();
    let role_names: HashMap<Uuid, &str> = roles.iter().map(|r| (r.id, r.name.as_str())).collect();

    let mut target_roles: HashMap<Uuid, Vec<String>> = HashMap::new();
    for assignment in TargetRoleAssignment::Entity::find().all(db).await? {
        if let Some(name) = role_names.get(&assignment.role_id) {
            target_roles
                .entry(assignment.target_id)
                .or_default()
                .push((*name).to_owned());
        }
    }

    let mut targets = Vec::new();
    for model in Target::Entity::find().all(db).await? {
        let mut target = TargetConfig::try_from(model)?;
        for slot in target.options.secrets_mut() {
            if let MaybeSecretRef::Inline(secret) = slot {
                *secret = StoredSecret::from(secret.reveal()?.expose_secret().clone());
            }
        }
        targets.push(Row {
            id: target.id,
            name: target.name,
            provider: target.provider,
            live: TargetSpec {
                description: target.description,
                group: target
                    .group_id
                    .and_then(|id| group_names.get(&id))
                    .map(|name| (*name).to_owned()),
                roles: target_roles.remove(&target.id).unwrap_or_default(),
                options: target.options,
                rate_limit_bytes_per_second: target.rate_limit_bytes_per_second,
                ticket_max_duration_seconds: target.ticket_max_duration_seconds,
                ticket_requests_disabled: target.ticket_requests_disabled,
                ticket_require_approval: target.ticket_require_approval,
                require_approval: target.require_approval,
                ticket_max_uses: target.ticket_max_uses,
            },
        });
    }

    Ok(Current {
        groups: groups
            .into_iter()
            .map(|group| Row {
                id: group.id,
                name: group.name,
                provider: group.provider,
                live: TargetGroupSpec {
                    description: group.description,
                    color: group.color,
                },
            })
            .collect(),
        roles: roles
            .into_iter()
            .map(|role| Row {
                id: role.id,
                name: role.name,
                provider: role.provider,
                live: RoleSpec {
                    description: role.description,
                    is_default: role.is_default,
                },
            })
            .collect(),
        targets,
    })
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use serde_json::json;
    use warpgate_common::ProviderId;
    use warpgate_gitops::plan::{Change, plan};
    use warpgate_gitops::types::Resource;

    use super::*;
    use crate::resources::roles::RoleDataRequest;
    use crate::resources::target_groups::TargetGroupDataRequest;
    use crate::resources::targets::{self, TargetDataRequest};
    use crate::resources::tests::db;
    use crate::resources::{Actor, roles, target_groups};

    #[tokio::test]
    async fn rows_written_from_a_spec_load_back_as_that_spec() {
        let db = db().await;
        let gitops = Actor::Provider(ProviderId::GITOPS);

        let prod = target_groups::create(
            &db,
            gitops,
            &TargetGroupDataRequest {
                name: "prod".into(),
                description: Some("Production".into()),
                color: None,
            },
        )
        .await
        .unwrap();
        let dba = roles::create(
            &db,
            gitops,
            &RoleDataRequest {
                name: "dba".into(),
                description: None,
                is_default: Some(true),
            },
        )
        .await
        .unwrap();
        let options =
            json!({"mysql": {"host": "h", "auth": {"kind": "password", "password": "hunter2"}}});
        let db_target = targets::create(
            &db,
            gitops,
            &TargetDataRequest {
                name: "db".into(),
                description: None,
                options: serde_json::from_value(options.clone()).unwrap(),
                rate_limit_bytes_per_second: Some(1000),
                group_id: Some(prod.id),
                ticket_max_duration_seconds: Some(3600),
                ticket_requests_disabled: false,
                ticket_require_approval: true,
                require_approval: false,
                ticket_max_uses: None,
            },
        )
        .await
        .unwrap();
        targets::add_role(&db, gitops, db_target.id, dba.id)
            .await
            .unwrap();

        let current = load_current(&db).await.unwrap();
        let desired: Vec<Resource> = [
            json!({"kind": "TargetGroup", "metadata": {"name": "prod"}, "spec": {"description": "Production"}}),
            json!({"kind": "Role", "metadata": {"name": "dba"}, "spec": {"is_default": true}}),
            json!({"kind": "Target", "metadata": {"name": "db"}, "spec": {
                "group": "prod",
                "roles": ["dba"],
                "options": options,
                "rate_limit_bytes_per_second": 1000,
                "ticket_max_duration_seconds": 3600,
                "ticket_require_approval": true,
            }}),
        ]
        .into_iter()
        .map(|mut value| {
            value["apiVersion"] = json!("warpgate/v1");
            Resource::from_value(&value).unwrap()
        })
        .collect();

        let plan = plan(ProviderId::GITOPS, &desired, &current);
        assert!(
            plan.changes
                .iter()
                .all(|c| matches!(c, Change::Unchanged { .. })),
            "{plan:?}"
        );
    }
}
