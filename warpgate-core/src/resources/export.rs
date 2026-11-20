//! Writes the rows no provider manages as resource files, for moving an
//! existing installation into GitOps.

use std::fmt::Write;

use sea_orm::ConnectionTrait;
use warpgate_common::version::{repository_file_url, warpgate_version};
use warpgate_common::{ProviderId, WarpgateError};
use warpgate_gitops::emit::to_yaml;
use warpgate_gitops::plan::{Prune, format_errors, plan};
use warpgate_gitops::types::{ApiVersion, Manifest, Metadata, Resource};
use warpgate_resources::{ResourceKind, Row};

use super::reconcile::load_current;
use crate::consts::BUILTIN_ADMIN_ROLE_NAME;

/// One YAML stream of every unmanaged row, in the order they apply. Each
/// sets `adopt_existing`, so syncing the file takes the rows over.
/// Inline credentials are written in plain text.
///
/// A row that a sync would refuse is left out and listed in a comment at the
/// top. One refused resource fails the whole sync.
pub async fn unmanaged<C: ConnectionTrait>(db: &C) -> Result<String, WarpgateError> {
    let current = load_current(db).await?;
    let mut resources = Vec::new();
    resources.extend(manifests(&current.groups, Resource::TargetGroup));
    resources.extend(
        manifests(&current.roles, Resource::Role)
            // A GitOps-owned admin role would lock admins out of editing it.
            // Files can still grant it.
            .filter(|role| role.metadata().name != BUILTIN_ADMIN_ROLE_NAME),
    );
    resources.extend(manifests(&current.ssh_client_keys, Resource::SshClientKey));
    resources.extend(manifests(&current.targets, Resource::Target));

    let plan = plan(ProviderId::GITOPS, &resources, &current, Prune::Off);
    resources.retain(|resource| {
        !plan.changes.iter().any(|change| {
            change.is_error()
                && change.kind() == ResourceKind::from(resource)
                && change.name() == resource.metadata().name
        })
    });

    let mut out = format!(
        "# Exported in version {version}\n",
        version = warpgate_version(),
    );
    if plan.has_errors() {
        out.push_str("#\n# Left out, because a sync would refuse them:\n");
        for refused in format_errors(&plan).lines() {
            // writing to a String cannot fail
            let _ = writeln!(out, "#   {refused}");
        }
    }
    out.push('\n');
    out.push_str(&to_yaml(&resources));

    let schema_tag = format!(
        "\n\n---\n# yaml-language-server: $schema={url}\n\n",
        url = repository_file_url("gitops-schema.json"),
    );
    out = out.replace("\n---\n", &schema_tag);
    Ok(out)
}

fn manifests<S: Clone>(
    rows: &[Row<S>],
    resource: impl Fn(Manifest<S>) -> Resource,
) -> impl Iterator<Item = Resource> {
    rows.iter()
        .filter(|row| row.provider.is_none())
        .map(move |row| {
            resource(Manifest {
                api_version: ApiVersion::V1,
                metadata: Metadata {
                    name: row.name.clone(),
                    adopt_existing: true,
                },
                spec: row.live.clone(),
            })
        })
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::DatabaseConnection;
    use serde_json::json;
    use uuid::Uuid;
    use warpgate_db_entities::ProviderSync::PlanAction;
    use warpgate_gitops::validate::check_files;

    use super::*;
    use crate::resources::roles::RoleDataRequest;
    use crate::resources::tests::{db, target};
    use crate::resources::{Actor, roles, targets};

    async fn planned(db: &DatabaseConnection, yaml: String) -> Vec<PlanAction> {
        let files = [("export.yaml".into(), yaml)];
        let resources = check_files(&files).unwrap().resources;
        let current = load_current(db).await.unwrap();
        plan(ProviderId::GITOPS, &resources, &current, Prune::Off)
            .changes
            .iter()
            .map(|change| change.action())
            .collect()
    }

    #[tokio::test]
    async fn exported_rows_plan_as_adoptions() {
        let db = db().await;
        for name in ["ops", BUILTIN_ADMIN_ROLE_NAME] {
            roles::create(
                &db,
                Actor::Admin,
                &RoleDataRequest {
                    name: name.into(),
                    description: None,
                    is_default: None,
                },
            )
            .await
            .unwrap();
        }

        let yaml = unmanaged(&db).await.unwrap();
        assert!(yaml.contains("# yaml-language-server: $schema="));
        assert_eq!(planned(&db, yaml).await, [PlanAction::Adopt]);
    }

    #[tokio::test]
    async fn a_row_that_a_sync_would_refuse_is_left_out() {
        let db = db().await;
        let gone = Uuid::new_v4();
        for (name, ssh) in [
            ("stranded", json!({"host": "h", "jump_host": gone})),
            (
                "keyless",
                json!({"host": "h", "auth": {"kind": "publickey", "key_id": gone}}),
            ),
        ] {
            targets::create(&db, Actor::Admin, &target(name, json!({ "ssh": ssh })))
                .await
                .unwrap();
        }

        let yaml = unmanaged(&db).await.unwrap();
        let refused = format!("#   blocked Target stranded: unknown Target `{gone}`\n");
        assert!(yaml.contains(&refused), "{yaml}");
        assert!(!yaml.contains("key_id"), "{yaml}");
        assert_eq!(planned(&db, yaml).await, [PlanAction::Adopt]);
    }
}
