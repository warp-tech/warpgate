pub mod reconcile;
pub mod roles;
pub mod target_groups;
pub mod targets;

use sea_orm::prelude::Expr;
use sea_orm::{ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter};
use uuid::Uuid;
use warpgate_common::{ProviderId, UserSessionId, WarpgateError};

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
    #[error("managed by {}", .0.label())]
    OwnedBy(ProviderId),
    #[error("created by hand; a provider may not change it")]
    Manual,

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

/// Who is writing. A row is changed only by whoever owns it: an admin for a
/// row created by hand, the owning provider for a reconciled one. HTTP
/// handlers always write as [`Actor::Admin`], so a provider's rows stay
/// read-only through the API, and a provider never overwrites a hand-made row
/// unless the resource is annotated `warpgate.dev/adopt-existing`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Actor {
    Admin,
    Provider(ProviderId),
}

impl Actor {
    fn may_write(self, owner: Option<ProviderId>) -> Result<(), ResourceError> {
        match (owner, self) {
            (None, Self::Admin) => Ok(()),
            (None, Self::Provider(_)) => Err(ResourceError::Manual),
            (Some(owner), Self::Provider(me)) if owner == me => Ok(()),
            (Some(owner), _) => Err(ResourceError::OwnedBy(owner)),
        }
    }

    const fn provider_id(self) -> Option<ProviderId> {
        match self {
            Self::Admin => None,
            Self::Provider(id) => Some(id),
        }
    }
}

/// Open sessions admitted by rows that a delete removed. Closing them needs the
/// session registry and cluster peers, so the caller does it once the delete has
/// committed, with [`crate::Services::close_admitted_sessions`].
#[derive(Debug)]
#[must_use]
pub struct AdmittedSessions(pub Vec<UserSessionId>);

/// Hands a hand-made row to `owner`, changing nothing else. The one write
/// that skips [`Actor::may_write`]: only applying a resource annotated with
/// `warpgate.dev/adopt-existing` reaches it, never an HTTP handler.
async fn set_owner<E: EntityTrait, C: ConnectionTrait>(
    db: &C,
    provider: E::Column,
    id_column: E::Column,
    id: Uuid,
    owner: ProviderId,
) -> Result<(), ResourceError> {
    E::update_many()
        .col_expr(provider, Expr::value(Some(owner)))
        .filter(id_column.eq(id))
        .exec(db)
        .await?;
    Ok(())
}

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
pub(crate) mod tests {
    use sea_orm::{Database, DatabaseConnection, EntityTrait};
    use serde_json::json;
    use uuid::Uuid;
    use warpgate_common::ProviderId;
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
    use warpgate_db_entities::{Target, TargetRoleAssignment};
    use warpgate_db_migrations::migrate_database;

    use super::roles::RoleDataRequest;
    use super::target_groups::TargetGroupDataRequest;
    use super::targets::TargetDataRequest;
    use super::*;

    pub(crate) async fn db() -> DatabaseConnection {
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
        let web = targets::create(&db, Actor::Admin, &ssh("web"))
            .await
            .unwrap();
        assert_eq!(web.rate_limit_bytes_per_second, Some(1000));

        let result = targets::create(&db, Actor::Admin, &ssh("web")).await;
        assert!(matches!(result, Err(ResourceError::NameTaken)));
        let result = targets::create(&db, Actor::Admin, &ssh("")).await;
        assert!(matches!(result, Err(ResourceError::EmptyName)));
        let http = target("web", json!({"http": {"url": "https://web"}}));
        let result = targets::update(&db, Actor::Admin, web.id, &http).await;
        assert!(matches!(result, Err(ResourceError::ProtocolChange)));
        let result = targets::update(&db, Actor::Admin, Uuid::new_v4(), &ssh("other")).await;
        assert!(matches!(result, Err(ResourceError::NotFound)));

        let dba = roles::create(&db, Actor::Admin, &role("dba", None))
            .await
            .unwrap();
        targets::add_role(&db, Actor::Admin, web.id, dba.id)
            .await
            .unwrap();
        let result = targets::add_role(&db, Actor::Admin, web.id, dba.id).await;
        assert!(matches!(result, Err(ResourceError::RoleAlreadyAssigned)));

        let admitted = targets::delete(&db, Actor::Admin, web.id).await.unwrap();
        assert!(admitted.0.is_empty());
        assert_eq!(assignments(&db).await, 0);
        let result = targets::delete(&db, Actor::Admin, web.id).await;
        assert!(matches!(result, Err(ResourceError::NotFound)));
    }

    #[tokio::test]
    async fn roles() {
        let db = db().await;
        let dba = roles::create(&db, Actor::Admin, &role("dba", Some(true)))
            .await
            .unwrap();
        let result = roles::create(&db, Actor::Admin, &role("dba", None)).await;
        assert!(matches!(result, Err(ResourceError::NameTaken)));

        let ops = roles::create(&db, Actor::Admin, &role("ops", None))
            .await
            .unwrap();
        assert!(!ops.is_default);
        let result = roles::update(&db, Actor::Admin, ops.id, &role("dba", None)).await;
        assert!(matches!(result, Err(ResourceError::NameTaken)));

        let renamed = roles::update(&db, Actor::Admin, dba.id, &role("dbas", None))
            .await
            .unwrap();
        assert_eq!(renamed.name, "dbas");
        assert!(renamed.is_default, "an omitted is_default stays as it was");

        let web = targets::create(&db, Actor::Admin, &ssh("web"))
            .await
            .unwrap();
        targets::add_role(&db, Actor::Admin, web.id, dba.id)
            .await
            .unwrap();
        roles::delete(&db, Actor::Admin, dba.id).await.unwrap();
        assert_eq!(assignments(&db).await, 0);
        let result = targets::remove_role(&db, Actor::Admin, web.id, dba.id).await;
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
        let prod = target_groups::create(&db, Actor::Admin, &group)
            .await
            .unwrap();
        let mut web = ssh("web");
        web.group_id = Some(prod.id);
        let web = targets::create(&db, Actor::Admin, &web).await.unwrap();

        target_groups::delete(&db, Actor::Admin, prod.id)
            .await
            .unwrap();
        let web = Target::Entity::find_by_id(web.id)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(web.group_id, None);
    }

    #[tokio::test]
    async fn provider_rows_are_read_only_for_everyone_else() {
        let db = db().await;
        let gitops = Actor::Provider(ProviderId::GITOPS);
        let other = Actor::Provider(ProviderId(Uuid::new_v4()));

        let web = targets::create(&db, gitops, &ssh("web")).await.unwrap();
        assert_eq!(web.provider, Some(ProviderId::GITOPS));
        let dba = roles::create(&db, gitops, &role("dba", None))
            .await
            .unwrap();
        let prod = target_groups::create(
            &db,
            gitops,
            &TargetGroupDataRequest {
                name: "prod".into(),
                description: None,
                color: None,
            },
        )
        .await
        .unwrap();

        fn owned<T: std::fmt::Debug>(r: Result<T, ResourceError>) {
            assert!(
                matches!(r, Err(ResourceError::OwnedBy(ProviderId::GITOPS))),
                "{r:?}"
            );
        }
        for actor in [Actor::Admin, other] {
            owned(targets::update(&db, actor, web.id, &ssh("web")).await);
            owned(targets::delete(&db, actor, web.id).await);
            owned(targets::add_role(&db, actor, web.id, dba.id).await);
            owned(targets::remove_role(&db, actor, web.id, dba.id).await);
            owned(roles::update(&db, actor, dba.id, &role("dba", None)).await);
            owned(roles::delete(&db, actor, dba.id).await);
            owned(target_groups::delete(&db, actor, prod.id).await);
        }

        targets::add_role(&db, gitops, web.id, dba.id)
            .await
            .unwrap();
        targets::update(&db, gitops, web.id, &ssh("web2"))
            .await
            .unwrap();
        let admitted = targets::delete(&db, gitops, web.id).await.unwrap();
        assert!(admitted.0.is_empty());

        // A row created by hand is never a provider's to change
        let manual = targets::create(&db, Actor::Admin, &ssh("manual"))
            .await
            .unwrap();
        assert_eq!(manual.provider, None);
        for result in [
            targets::update(&db, gitops, manual.id, &ssh("manual"))
                .await
                .map(|_| ()),
            targets::delete(&db, gitops, manual.id).await.map(|_| ()),
            targets::add_role(&db, gitops, manual.id, dba.id).await,
        ] {
            assert!(matches!(result, Err(ResourceError::Manual)), "{result:?}");
        }
        targets::update(&db, Actor::Admin, manual.id, &ssh("manual"))
            .await
            .unwrap();
    }
}
