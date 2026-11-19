pub mod roles;
pub mod target_groups;
pub mod targets;

use sea_orm::DbErr;
use warpgate_common::{UserSessionId, WarpgateError};

use crate::db::is_unique_violation;

#[derive(Debug, thiserror::Error)]
pub enum ResourceError {
    #[error("name is empty")]
    EmptyName,
    #[error("name already taken")]
    NameTaken,
    #[error("not found")]
    NotFound,
    #[error("a target's protocol cannot be changed after creation")]
    ProtocolChange,
    #[error("the role is already assigned")]
    RoleAlreadyAssigned,

    #[error(transparent)]
    Other(#[from] WarpgateError),
}

impl From<DbErr> for ResourceError {
    fn from(err: DbErr) -> Self {
        Self::Other(err.into())
    }
}

impl From<ResourceError> for WarpgateError {
    fn from(err: ResourceError) -> Self {
        match err {
            ResourceError::Other(err) => err,
            err => Self::Other(Box::new(err)),
        }
    }
}

/// Open sessions admitted by rows that a delete removed. Closing them needs the
/// session registry and cluster peers, so the caller does it once the delete has
/// committed, with [`crate::Services::close_admitted_sessions`].
#[must_use]
pub struct AdmittedSessions(pub Vec<UserSessionId>);

const fn check_name(name: &str) -> Result<(), ResourceError> {
    if name.is_empty() {
        return Err(ResourceError::EmptyName);
    }
    Ok(())
}

fn name_taken(err: DbErr) -> ResourceError {
    if is_unique_violation(&err) {
        ResourceError::NameTaken
    } else {
        err.into()
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::{ActiveModelTrait, Database, DatabaseConnection, EntityTrait, Set};
    use serde_json::json;
    use time::OffsetDateTime;
    use uuid::Uuid;
    use warpgate_common::TargetSessionId;
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
    use warpgate_db_entities::{Target, TargetRoleAssignment, TargetSession, UserSession};
    use warpgate_db_migrations::migrate_database;

    use super::roles::RoleDataRequest;
    use super::target_groups::TargetGroupDataRequest;
    use super::targets::TargetDataRequest;
    use super::*;

    async fn db() -> DatabaseConnection {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        db
    }

    fn target(name: &str, options: serde_json::Value) -> TargetDataRequest {
        TargetDataRequest {
            name: name.into(),
            description: None,
            options: serde_json::from_value(options).unwrap(),
            rate_limit_bytes_per_second: Some(1000),
            group_id: None,
            ticket_max_duration_seconds: None,
            ticket_requests_disabled: false,
            ticket_require_approval: false,
            require_approval: false,
            ticket_max_uses: None,
        }
    }

    fn ssh(name: &str) -> TargetDataRequest {
        target(name, json!({"ssh": {"host": "h"}}))
    }

    fn role(name: &str, is_default: Option<bool>) -> RoleDataRequest {
        RoleDataRequest {
            name: name.into(),
            description: None,
            is_default,
        }
    }

    async fn assignments(db: &DatabaseConnection) -> usize {
        TargetRoleAssignment::Entity::find()
            .all(db)
            .await
            .unwrap()
            .len()
    }

    #[tokio::test]
    async fn targets() {
        let db = db().await;
        let web = targets::create(&db, &ssh("web")).await.unwrap();
        assert_eq!(web.rate_limit_bytes_per_second, Some(1000));

        let result = targets::create(&db, &ssh("web")).await;
        assert!(matches!(result, Err(ResourceError::NameTaken)));
        let result = targets::create(&db, &ssh("")).await;
        assert!(matches!(result, Err(ResourceError::EmptyName)));
        let http = target("web", json!({"http": {"url": "https://web"}}));
        let result = targets::update(&db, web.id, &http).await;
        assert!(matches!(result, Err(ResourceError::ProtocolChange)));
        let result = targets::update(&db, Uuid::new_v4(), &ssh("other")).await;
        assert!(matches!(result, Err(ResourceError::NotFound)));

        let dba = roles::create(&db, &role("dba", None)).await.unwrap();
        targets::add_role(&db, web.id, dba.id).await.unwrap();
        let result = targets::add_role(&db, web.id, dba.id).await;
        assert!(matches!(result, Err(ResourceError::RoleAlreadyAssigned)));

        let admitted = targets::delete(&db, web.id).await.unwrap();
        assert!(admitted.0.is_empty());
        assert_eq!(assignments(&db).await, 0);
        let result = targets::delete(&db, web.id).await;
        assert!(matches!(result, Err(ResourceError::NotFound)));
    }

    #[tokio::test]
    async fn target_update_and_delete_collect_open_sessions() {
        let db = db().await;
        let web = targets::create(&db, &ssh("web")).await.unwrap();
        let user_session_id = UserSessionId(Uuid::new_v4());
        UserSession::ActiveModel {
            id: Set(user_session_id),
            username: Set(Some("alice".into())),
            remote_address: Set("127.0.0.1:1234".into()),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            protocol: Set("Kubernetes".into()),
            user_id: Set(None),
            auth_state_node_id: Set(None),
            node_id: Set(None),
        }
        .insert(&db)
        .await
        .unwrap();
        TargetSession::ActiveModel {
            id: Set(TargetSessionId(Uuid::new_v4())),
            user_session_id: Set(user_session_id),
            target_snapshot: Set("{}".into()),
            target_id: Set(web.id),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            ticket_id: Set(None),
            node_id: Set(None),
        }
        .insert(&db)
        .await
        .unwrap();

        // Non-connection metadata edits keep existing sessions running.
        let mut metadata_only = ssh("web");
        metadata_only.description = Some("updated".into());
        metadata_only.rate_limit_bytes_per_second = Some(2000);
        let (_, admitted) = targets::update(&db, web.id, &metadata_only).await.unwrap();
        assert!(admitted.0.is_empty());

        // Changing target options, name, or enabling require_approval returns open sessions to close.
        let mut changed_options = target("web", json!({"ssh": {"host": "h2"}}));
        let (_, admitted) = targets::update(&db, web.id, &changed_options)
            .await
            .unwrap();
        assert_eq!(admitted.0, vec![user_session_id]);

        changed_options.require_approval = true;
        let (_, admitted) = targets::update(&db, web.id, &changed_options)
            .await
            .unwrap();
        assert_eq!(admitted.0, vec![user_session_id]);

        // Deleting a target also returns open role-admitted sessions.
        let admitted = targets::delete(&db, web.id).await.unwrap();
        assert_eq!(admitted.0, vec![user_session_id]);
    }

    #[tokio::test]
    async fn roles() {
        let db = db().await;
        let dba = roles::create(&db, &role("dba", Some(true))).await.unwrap();
        let result = roles::create(&db, &role("dba", None)).await;
        assert!(matches!(result, Err(ResourceError::NameTaken)));

        let ops = roles::create(&db, &role("ops", None)).await.unwrap();
        assert!(!ops.is_default);
        let result = roles::update(&db, ops.id, &role("dba", None)).await;
        assert!(matches!(result, Err(ResourceError::NameTaken)));

        let renamed = roles::update(&db, dba.id, &role("dbas", None))
            .await
            .unwrap();
        assert_eq!(renamed.name, "dbas");
        assert!(renamed.is_default, "an omitted is_default stays as it was");

        let web = targets::create(&db, &ssh("web")).await.unwrap();
        targets::add_role(&db, web.id, dba.id).await.unwrap();
        roles::delete(&db, dba.id).await.unwrap();
        assert_eq!(assignments(&db).await, 0);
        let result = targets::remove_role(&db, web.id, dba.id).await;
        assert!(matches!(result, Err(ResourceError::NotFound)));
    }

    #[tokio::test]
    async fn deleting_a_group_ungroups_its_targets() {
        let db = db().await;
        let group = TargetGroupDataRequest {
            name: "prod".into(),
            description: None,
            color: None,
        };
        let prod = target_groups::create(&db, &group).await.unwrap();
        let mut web = ssh("web");
        web.group_id = Some(prod.id);
        let web = targets::create(&db, &web).await.unwrap();

        target_groups::delete(&db, prod.id).await.unwrap();
        let web = Target::Entity::find_by_id(web.id)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(web.group_id, None);
    }
}
