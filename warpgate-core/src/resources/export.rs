//! Writes the rows no provider manages as resource files, for moving an
//! existing installation into GitOps.

use sea_orm::ConnectionTrait;
use warpgate_common::WarpgateError;
use warpgate_common::version::{repository_file_url, warpgate_version};
use warpgate_gitops::emit::to_yaml;
use warpgate_gitops::plan::Row;
use warpgate_gitops::types::{ApiVersion, Manifest, Metadata, Resource};

use super::reconcile::load_current;
use crate::consts::BUILTIN_ADMIN_ROLE_NAME;

/// One YAML stream of every unmanaged row, in the order they apply. Each
/// sets `adopt_existing`, so syncing the file takes the rows over.
/// Inline credentials are written in plain text.
pub async fn unmanaged<C: ConnectionTrait>(db: &C) -> Result<String, WarpgateError> {
    let current = load_current(db).await?;
    let mut resources = Vec::new();
    resources.extend(manifests(current.groups, Resource::TargetGroup));
    resources.extend(manifests(
        current
            .roles
            .into_iter()
            // A GitOps-owned admin role would lock admins out of editing it.
            // Files can still grant it.
            .filter(|row| row.name != BUILTIN_ADMIN_ROLE_NAME)
            .collect(),
        Resource::Role,
    ));
    resources.extend(manifests(current.ssh_client_keys, Resource::SshClientKey));
    resources.extend(manifests(current.targets, Resource::Target));
    Ok(format!(
        "# Exported in version {version}\n# yaml-language-server: $schema={schema}\n\n{yaml}",
        version = warpgate_version(),
        schema = repository_file_url("gitops-schema.json"),
        yaml = to_yaml(&resources),
    ))
}

fn manifests<S>(
    rows: Vec<Row<S>>,
    resource: impl Fn(Manifest<S>) -> Resource,
) -> impl Iterator<Item = Resource> {
    rows.into_iter()
        .filter(|row| row.provider.is_none())
        .map(move |row| {
            resource(Manifest {
                api_version: ApiVersion::V1,
                metadata: Metadata {
                    name: row.name,
                    adopt_existing: true,
                },
                spec: row.live,
            })
        })
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use warpgate_gitops::plan::{Prune, plan};
    use warpgate_gitops::validate::check_files;

    use super::*;
    use crate::resources::roles::RoleDataRequest;
    use crate::resources::tests::db;
    use crate::resources::{Actor, roles};

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
        let files = [("export.yaml".into(), yaml)];
        let resources = check_files(&files).unwrap().resources;
        assert_eq!(resources.len(), 1);
        let current = load_current(&db).await.unwrap();
        let planned = plan(
            warpgate_common::ProviderId::GITOPS,
            &resources,
            &current,
            Prune::Off,
        );
        assert_eq!(
            planned
                .changes
                .iter()
                .map(|c| c.action())
                .collect::<Vec<_>>(),
            [warpgate_db_entities::ProviderSync::PlanAction::Adopt]
        );
    }
}
