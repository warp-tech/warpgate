//! Syncs targets, target groups and roles from a static YAML file into the
//! database, so they can be managed by an external system (e.g. a CMDB export)
//! instead of the admin API/UI. See [`sync_static_targets_file`].
//!
//! Rows created by a sync are tagged `static_managed = true`. Every sync is a
//! full reconciliation against the file's current contents: rows are
//! upserted by name, and any previously-synced row whose name is no longer
//! present in the file is deleted. A name that collides with an existing
//! admin-managed (`static_managed = false`) row is left alone and the
//! conflicting file entry is skipped, so a sync can never clobber something
//! created by hand.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use sea_orm::prelude::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, ModelTrait, QueryFilter, Set,
};
use serde::Deserialize;
use tracing::{info, warn};
use uuid::Uuid;
use warpgate_common::{TargetOptions, WarpgateError};
use warpgate_db_entities::Target::TargetKind;
use warpgate_db_entities::TargetGroup::BootstrapThemeColor;
use warpgate_db_entities::{KnownHost, Role, Target, TargetGroup, TargetRoleAssignment, Ticket, TicketRequest};

#[derive(Debug, Deserialize, Default)]
pub struct StaticTargetsFile {
    #[serde(default)]
    pub roles: Vec<StaticRole>,
    #[serde(default)]
    pub target_groups: Vec<StaticTargetGroup>,
    #[serde(default)]
    pub targets: Vec<StaticTarget>,
}

#[derive(Debug, Deserialize)]
pub struct StaticRole {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Deserialize)]
pub struct StaticTargetGroup {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub color: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct StaticTarget {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Name of a group in this file's `target_groups` list.
    #[serde(default)]
    pub group: Option<String>,
    /// Names of roles (existing ones, or ones defined in this file's `roles`
    /// list) allowed to access this target.
    #[serde(default)]
    pub allow_roles: Vec<String>,
    #[serde(default)]
    pub rate_limit_bytes_per_second: Option<u32>,
    #[serde(flatten)]
    pub options: TargetOptions,
}

/// Read and parse `path`, then reconcile the database's static-managed
/// targets/target groups/roles to match it.
pub async fn sync_static_targets_file(
    db: &DatabaseConnection,
    path: &Path,
) -> Result<(), WarpgateError> {
    let contents = std::fs::read_to_string(path)?;
    let file: StaticTargetsFile = serde_yaml::from_str(&contents)?;

    sync_roles(db, &file.roles).await?;
    let group_ids = sync_target_groups(db, &file.target_groups).await?;
    sync_targets(db, &file.targets, &group_ids).await?;

    info!(
        path = %path.display(),
        roles = file.roles.len(),
        target_groups = file.target_groups.len(),
        targets = file.targets.len(),
        "Synced static targets file"
    );

    Ok(())
}

fn parse_bootstrap_color(color: Option<&str>) -> Option<BootstrapThemeColor> {
    let color = color?;
    match color.to_ascii_lowercase().as_str() {
        "primary" => Some(BootstrapThemeColor::Primary),
        "secondary" => Some(BootstrapThemeColor::Secondary),
        "success" => Some(BootstrapThemeColor::Success),
        "danger" => Some(BootstrapThemeColor::Danger),
        "warning" => Some(BootstrapThemeColor::Warning),
        "info" => Some(BootstrapThemeColor::Info),
        "light" => Some(BootstrapThemeColor::Light),
        "dark" => Some(BootstrapThemeColor::Dark),
        _ => {
            warn!(color, "Unknown target group color in static targets file, ignoring");
            None
        }
    }
}

async fn sync_roles(
    db: &DatabaseConnection,
    roles: &[StaticRole],
) -> Result<(), WarpgateError> {
    let mut existing_by_name: HashMap<String, Role::Model> = Role::Entity::find()
        .filter(Role::Column::StaticManaged.eq(true))
        .all(db)
        .await?
        .into_iter()
        .map(|m| (m.name.clone(), m))
        .collect();

    let mut seen_names = HashSet::new();

    for role in roles {
        if !seen_names.insert(role.name.clone()) {
            warn!(name = %role.name, "Duplicate role name in static targets file, ignoring repeat");
            continue;
        }

        if Role::Entity::find()
            .filter(Role::Column::Name.eq(role.name.clone()))
            .filter(Role::Column::StaticManaged.eq(false))
            .one(db)
            .await?
            .is_some()
        {
            warn!(
                name = %role.name,
                "Skipping static role: an admin-managed role with the same name already exists"
            );
            continue;
        }

        match existing_by_name.remove(&role.name) {
            Some(existing) => {
                let mut active: Role::ActiveModel = existing.into();
                active.description = Set(role.description.clone());
                active.update(db).await?;
            }
            None => {
                Role::ActiveModel {
                    id: Set(Uuid::new_v4()),
                    name: Set(role.name.clone()),
                    description: Set(role.description.clone()),
                    is_default: Set(false),
                    static_managed: Set(true),
                }
                .insert(db)
                .await?;
            }
        }
    }

    for (name, model) in existing_by_name {
        info!(name = %name, "Removing static role no longer present in targets file");
        TargetRoleAssignment::Entity::delete_many()
            .filter(TargetRoleAssignment::Column::RoleId.eq(model.id))
            .exec(db)
            .await?;
        warpgate_db_entities::UserRoleAssignment::Entity::delete_many()
            .filter(warpgate_db_entities::UserRoleAssignment::Column::RoleId.eq(model.id))
            .exec(db)
            .await?;
        model.delete(db).await?;
    }

    Ok(())
}

async fn sync_target_groups(
    db: &DatabaseConnection,
    groups: &[StaticTargetGroup],
) -> Result<HashMap<String, Uuid>, WarpgateError> {
    let mut existing_by_name: HashMap<String, TargetGroup::Model> = TargetGroup::Entity::find()
        .filter(TargetGroup::Column::StaticManaged.eq(true))
        .all(db)
        .await?
        .into_iter()
        .map(|m| (m.name.clone(), m))
        .collect();

    let mut ids = HashMap::new();
    let mut seen_names = HashSet::new();

    for group in groups {
        if !seen_names.insert(group.name.clone()) {
            warn!(name = %group.name, "Duplicate target group name in static targets file, ignoring repeat");
            continue;
        }

        if TargetGroup::Entity::find()
            .filter(TargetGroup::Column::Name.eq(group.name.clone()))
            .filter(TargetGroup::Column::StaticManaged.eq(false))
            .one(db)
            .await?
            .is_some()
        {
            warn!(
                name = %group.name,
                "Skipping static target group: an admin-managed group with the same name already exists"
            );
            continue;
        }

        let color = parse_bootstrap_color(group.color.as_deref());

        let id = match existing_by_name.remove(&group.name) {
            Some(existing) => {
                let id = existing.id;
                let mut active: TargetGroup::ActiveModel = existing.into();
                active.description = Set(group.description.clone());
                active.color = Set(color);
                active.update(db).await?;
                id
            }
            None => {
                let id = Uuid::new_v4();
                TargetGroup::ActiveModel {
                    id: Set(id),
                    name: Set(group.name.clone()),
                    description: Set(group.description.clone()),
                    color: Set(color),
                    static_managed: Set(true),
                }
                .insert(db)
                .await?;
                id
            }
        };

        ids.insert(group.name.clone(), id);
    }

    for (name, model) in existing_by_name {
        info!(name = %name, "Removing static target group no longer present in targets file");
        Target::Entity::update_many()
            .col_expr(Target::Column::GroupId, Expr::value(Option::<Uuid>::None))
            .filter(Target::Column::GroupId.eq(model.id))
            .exec(db)
            .await?;
        model.delete(db).await?;
    }

    Ok(ids)
}

async fn sync_targets(
    db: &DatabaseConnection,
    targets: &[StaticTarget],
    group_ids: &HashMap<String, Uuid>,
) -> Result<(), WarpgateError> {
    let mut existing_by_name: HashMap<String, Target::Model> = Target::Entity::find()
        .filter(Target::Column::StaticManaged.eq(true))
        .all(db)
        .await?
        .into_iter()
        .map(|m| (m.name.clone(), m))
        .collect();

    let mut seen_names = HashSet::new();

    for t in targets {
        if !seen_names.insert(t.name.clone()) {
            warn!(name = %t.name, "Duplicate target name in static targets file, ignoring repeat");
            continue;
        }

        if Target::Entity::find()
            .filter(Target::Column::Name.eq(t.name.clone()))
            .filter(Target::Column::StaticManaged.eq(false))
            .one(db)
            .await?
            .is_some()
        {
            warn!(
                name = %t.name,
                "Skipping static target: an admin-managed target with the same name already exists"
            );
            continue;
        }

        let group_id = match &t.group {
            Some(group_name) => match group_ids.get(group_name) {
                Some(id) => Some(*id),
                None => {
                    warn!(
                        target = %t.name,
                        group = %group_name,
                        "Unknown target group referenced, leaving target ungrouped"
                    );
                    None
                }
            },
            None => None,
        };

        let mut options = t.options.clone();
        match &mut options {
            TargetOptions::MySql(opts) => opts.normalize(),
            TargetOptions::Postgres(opts) => opts.normalize(),
            _ => {}
        }
        let kind = TargetKind::from(&options);
        let options_json = serde_json::to_value(&options)?;

        let target_id = match existing_by_name.remove(&t.name) {
            Some(existing) if existing.kind == kind => {
                let id = existing.id;
                let mut active: Target::ActiveModel = existing.into();
                active.description = Set(t.description.clone());
                active.options = Set(options_json);
                active.rate_limit_bytes_per_second =
                    Set(t.rate_limit_bytes_per_second.map(i64::from));
                active.group_id = Set(group_id);
                active.update(db).await?;
                id
            }
            Some(_) => {
                warn!(
                    name = %t.name,
                    "Skipping static target: its type changed since the last sync; delete it via the admin API first if you want to recreate it"
                );
                continue;
            }
            None => {
                let id = Uuid::new_v4();
                Target::ActiveModel {
                    id: Set(id),
                    name: Set(t.name.clone()),
                    description: Set(t.description.clone()),
                    kind: Set(kind),
                    options: Set(options_json),
                    rate_limit_bytes_per_second: Set(t.rate_limit_bytes_per_second.map(i64::from)),
                    group_id: Set(group_id),
                    ticket_max_duration_seconds: Set(None),
                    ticket_requests_disabled: Set(false),
                    ticket_require_approval: Set(false),
                    ticket_max_uses: Set(None),
                    static_managed: Set(true),
                }
                .insert(db)
                .await?;
                id
            }
        };

        sync_target_roles(db, target_id, &t.allow_roles).await?;
    }

    for (name, model) in existing_by_name {
        info!(name = %name, "Removing static target no longer present in targets file");
        delete_target_cascade(db, model).await?;
    }

    Ok(())
}

async fn sync_target_roles(
    db: &DatabaseConnection,
    target_id: Uuid,
    allow_roles: &[String],
) -> Result<(), WarpgateError> {
    let mut desired_ids = HashSet::new();
    for role_name in allow_roles {
        match Role::Entity::find()
            .filter(Role::Column::Name.eq(role_name.clone()))
            .one(db)
            .await?
        {
            Some(role) => {
                desired_ids.insert(role.id);
            }
            None => warn!(role = %role_name, "Unknown role referenced by a static target, ignoring"),
        }
    }

    let existing = TargetRoleAssignment::Entity::find()
        .filter(TargetRoleAssignment::Column::TargetId.eq(target_id))
        .all(db)
        .await?;

    for assignment in existing {
        if desired_ids.remove(&assignment.role_id) {
            continue;
        }
        TargetRoleAssignment::Entity::delete_many()
            .filter(TargetRoleAssignment::Column::Id.eq(assignment.id))
            .exec(db)
            .await?;
    }

    for role_id in desired_ids {
        TargetRoleAssignment::ActiveModel {
            target_id: Set(target_id),
            role_id: Set(role_id),
            ..Default::default()
        }
        .insert(db)
        .await?;
    }

    Ok(())
}

async fn delete_target_cascade(
    db: &DatabaseConnection,
    target: Target::Model,
) -> Result<(), WarpgateError> {
    TargetRoleAssignment::Entity::delete_many()
        .filter(TargetRoleAssignment::Column::TargetId.eq(target.id))
        .exec(db)
        .await?;

    TicketRequest::Entity::delete_many()
        .filter(TicketRequest::Column::TargetId.eq(target.id))
        .exec(db)
        .await?;

    Ticket::Entity::delete_many()
        .filter(Ticket::Column::TargetId.eq(target.id))
        .exec(db)
        .await?;

    if target.kind == TargetKind::Ssh
        && let Ok(TargetOptions::Ssh(ssh_options)) =
            serde_json::from_value(target.options.clone())
    {
        KnownHost::Entity::delete_many()
            .filter(KnownHost::Column::Host.eq(&ssh_options.host))
            .filter(KnownHost::Column::Port.eq(i32::from(ssh_options.port)))
            .exec(db)
            .await?;
    }

    target.delete(db).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::Database;
    use tempfile::NamedTempFile;

    use super::*;

    async fn test_db() -> DatabaseConnection {
        warpgate_db_entities::Parameters::set_config_migration_values(
            warpgate_db_entities::Parameters::ConfigMigrationValues::default(),
        );
        let db = Database::connect("sqlite::memory:").await.unwrap();
        warpgate_db_migrations::migrate_database(&db).await.unwrap();
        db
    }

    fn write_file(contents: &str) -> NamedTempFile {
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), contents).unwrap();
        file
    }

    #[test]
    fn parses_minimal_target() {
        let file: StaticTargetsFile = serde_yaml::from_str(
            r#"
targets:
  - name: web01
    ssh:
      host: 10.0.0.1
"#,
        )
        .unwrap();
        assert_eq!(file.targets.len(), 1);
        assert_eq!(file.targets[0].name, "web01");
        assert!(matches!(file.targets[0].options, TargetOptions::Ssh(_)));
    }

    #[test]
    fn parses_groups_and_roles() {
        let file: StaticTargetsFile = serde_yaml::from_str(
            r#"
roles:
  - name: netbox
    description: from netbox
target_groups:
  - name: prod
    color: primary
targets:
  - name: web01
    group: prod
    allow_roles: [netbox]
    ssh:
      host: 10.0.0.1
"#,
        )
        .unwrap();
        assert_eq!(file.roles[0].name, "netbox");
        assert_eq!(file.target_groups[0].name, "prod");
        assert_eq!(file.targets[0].group.as_deref(), Some("prod"));
        assert_eq!(file.targets[0].allow_roles, vec!["netbox".to_string()]);
    }

    #[tokio::test]
    async fn syncs_insert_update_delete_cycle() {
        let db = test_db().await;

        let file = write_file(
            r#"
roles:
  - name: netbox
target_groups:
  - name: prod
targets:
  - name: web01
    group: prod
    allow_roles: [netbox]
    ssh:
      host: 10.0.0.1
"#,
        );

        sync_static_targets_file(&db, file.path()).await.unwrap();

        let target = Target::Entity::find()
            .filter(Target::Column::Name.eq("web01"))
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert!(target.static_managed);
        assert!(target.group_id.is_some());

        let roles = target.find_related(Role::Entity).all(&db).await.unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].name, "netbox");

        // Update: change the host and drop the role assignment.
        std::fs::write(
            file.path(),
            r#"
roles:
  - name: netbox
target_groups:
  - name: prod
targets:
  - name: web01
    group: prod
    ssh:
      host: 10.0.0.2
"#,
        )
        .unwrap();
        sync_static_targets_file(&db, file.path()).await.unwrap();

        let target = Target::Entity::find_by_id(target.id)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        let options: TargetOptions = serde_json::from_value(target.options.clone()).unwrap();
        assert!(matches!(options, TargetOptions::Ssh(ref o) if o.host == "10.0.0.2"));
        let roles = target.find_related(Role::Entity).all(&db).await.unwrap();
        assert!(roles.is_empty());

        // Delete: remove the target from the file entirely.
        std::fs::write(
            file.path(),
            r#"
target_groups:
  - name: prod
targets: []
"#,
        )
        .unwrap();
        sync_static_targets_file(&db, file.path()).await.unwrap();

        assert!(
            Target::Entity::find()
                .filter(Target::Column::Name.eq("web01"))
                .one(&db)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn leaves_admin_managed_rows_with_a_colliding_name_untouched() {
        let db = test_db().await;

        let options: TargetOptions =
            serde_json::from_str(r#"{"ssh":{"host":"10.0.0.9"}}"#).unwrap();
        Target::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set("web01".into()),
            description: Set(String::new()),
            kind: Set(TargetKind::Ssh),
            options: Set(serde_json::to_value(&options).unwrap()),
            rate_limit_bytes_per_second: Set(None),
            group_id: Set(None),
            ticket_max_duration_seconds: Set(None),
            ticket_requests_disabled: Set(false),
            ticket_require_approval: Set(false),
            ticket_max_uses: Set(None),
            static_managed: Set(false),
        }
        .insert(&db)
        .await
        .unwrap();

        let file = write_file(
            r#"
targets:
  - name: web01
    ssh:
      host: 10.0.0.1
"#,
        );
        sync_static_targets_file(&db, file.path()).await.unwrap();

        let target = Target::Entity::find()
            .filter(Target::Column::Name.eq("web01"))
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert!(!target.static_managed);
        let options: TargetOptions = serde_json::from_value(target.options).unwrap();
        assert!(matches!(options, TargetOptions::Ssh(ref o) if o.host == "10.0.0.9"));
    }
}
