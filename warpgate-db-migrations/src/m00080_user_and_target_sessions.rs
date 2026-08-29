use std::collections::HashMap;

use sea_orm::{ConnectionTrait, DbBackend, Order, Schema};
use sea_orm_migration::prelude::*;
use uuid::Uuid;

use crate::m00002_create_session::session;

const BACKFILL_BATCH: u64 = 1000;

/// The target id for a session that connected before `target_id` existed
/// (m00077 added the column without a backfill), recovered from its snapshot:
/// by the id embedded in the snapshot first, then by target name against the
/// current `targets` table for older snapshots that carry no id, then the nil
/// UUID for a snapshot that resolves to nothing at all.
fn recover_target_id(snapshot: &str, targets_by_name: &HashMap<String, Uuid>) -> Uuid {
    let value: Option<serde_json::Value> = serde_json::from_str(snapshot).ok();
    let by_embedded_id = value
        .as_ref()
        .and_then(|value| value.get("id"))
        .and_then(|id| id.as_str())
        .and_then(|id| Uuid::parse_str(id).ok());
    let by_name = || {
        value
            .as_ref()
            .and_then(|value| value.get("name"))
            .and_then(|name| name.as_str())
            .and_then(|name| targets_by_name.get(name))
            .copied()
    };
    by_embedded_id.or_else(by_name).unwrap_or_else(Uuid::nil)
}

/// Fills `sessions.target_id` for rows that carry a `target_snapshot` but no
/// `target_id`, so the "never reached a target" cleanup below (and the NOT
/// NULL tightening after it) can key on `target_snapshot` alone.
async fn backfill_target_ids(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();
    let backend = db.get_database_backend();

    let sessions = Alias::new("sessions");
    let id_col = Alias::new("id");
    let snapshot_col = Alias::new("target_snapshot");
    let target_id_col = Alias::new("target_id");

    let targets_by_name: HashMap<String, Uuid> = {
        let select = Query::select()
            .column(Alias::new("name"))
            .column(id_col.clone())
            .from(Alias::new("targets"))
            .to_owned();
        let mut map = HashMap::new();
        for row in db.query_all(backend.build(&select)).await? {
            map.insert(
                row.try_get::<String>("", "name")?,
                row.try_get::<Uuid>("", "id")?,
            );
        }
        map
    };

    // Keyset pagination: updated rows stop matching the filter, but an offset
    // over a shrinking result set would skip rows.
    let mut last_id: Option<Uuid> = None;
    loop {
        let mut select = Query::select()
            .column(id_col.clone())
            .column(snapshot_col.clone())
            .from(sessions.clone())
            .and_where(Expr::col(target_id_col.clone()).is_null())
            .and_where(Expr::col(snapshot_col.clone()).is_not_null())
            .order_by(id_col.clone(), Order::Asc)
            .limit(BACKFILL_BATCH)
            .to_owned();
        if let Some(last_id) = last_id {
            select.and_where(Expr::col(id_col.clone()).gt(last_id));
        }

        let rows = db.query_all(backend.build(&select)).await?;
        let done = (rows.len() as u64) < BACKFILL_BATCH;

        for row in &rows {
            let id: Uuid = row.try_get("", "id")?;
            last_id = Some(id);

            let snapshot: String = row.try_get("", "target_snapshot")?;
            let update = Query::update()
                .table(sessions.clone())
                .value(
                    target_id_col.clone(),
                    recover_target_id(&snapshot, &targets_by_name),
                )
                .and_where(Expr::col(id_col.clone()).eq(id))
                .to_owned();
            db.execute(backend.build(&update)).await?;
        }

        if done {
            return Ok(());
        }
    }
}

pub mod user_session {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "user_sessions")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub username: Option<String>,
        pub user_id: Option<Uuid>,
        pub remote_address: String,
        pub started: OffsetDateTime,
        pub ended: Option<OffsetDateTime>,
        pub protocol: String,
        /// NULL for shared-lifecycle (HTTP) sessions — no node owns them.
        pub node_id: Option<Uuid>,
        pub auth_state_node_id: Option<Uuid>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let schema = Schema::new(manager.get_database_backend());
        manager
            .create_table(schema.create_table_from_entity(user_session::Entity))
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(session::Entity)
                    .add_column(ColumnDef::new(Alias::new("user_session_id")).uuid().null())
                    .to_owned(),
            )
            .await?;

        // Existing sessions represented both the login and its only target
        // connection. Preserve that history as a one-to-one parent/child pair.
        manager
            .get_connection()
            .execute_unprepared(
                "INSERT INTO user_sessions \
                 (id, username, user_id, remote_address, started, ended, protocol, node_id) \
                 SELECT s.id, s.username, s.user_id, s.remote_address, s.started, s.ended, \
                 s.protocol, s.node_id \
                 FROM sessions s",
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared("UPDATE sessions SET user_session_id = id")
            .await?;

        // `sessions.node_id` becomes nullable again (reverting m00072's
        // tightening): NULL now means shared lifecycle, not a missing value.
        // SQLite never enforced the NOT NULL (see m00072) and needs no change.
        if manager.get_database_backend() != DbBackend::Sqlite {
            manager
                .alter_table(
                    Table::alter()
                        .table(session::Entity)
                        .modify_column(ColumnDef::new(Alias::new("node_id")).uuid().null())
                        .to_owned(),
                )
                .await?;
        }

        // Shared-lifecycle (HTTP) sessions have no owning node: any node
        // serves them and they must survive the reaper ending a dead node's
        // sessions — including the node that wrote them before this upgrade.
        manager
            .get_connection()
            .execute_unprepared("UPDATE user_sessions SET node_id = NULL WHERE protocol = 'HTTP'")
            .await?;
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sessions SET node_id = NULL WHERE user_session_id IN \
                 (SELECT id FROM user_sessions WHERE node_id IS NULL)",
            )
            .await?;

        backfill_target_ids(manager).await?;

        // A pre-split row with no target snapshot never reached a target and
        // was only ever a login: it lives on as the `user_sessions` row
        // created above, and its `sessions` row goes. (`target_id` is not the
        // discriminator — it is NULL on every row predating m00077.) Recording
        // rows go first: pre-split SSH recorded the target-selection menu, so
        // login-only rows can carry recordings, and an orphan must not survive
        // its session.
        manager
            .get_connection()
            .execute_unprepared(
                "DELETE FROM recordings WHERE session_id IN \
                 (SELECT id FROM sessions WHERE target_snapshot IS NULL)",
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sessions WHERE target_snapshot IS NULL")
            .await?;

        Ok(())
    }

    /// Reverses the schema, not the data: the login identity now lives only in
    /// `user_sessions`, which this drops, and the login-only `sessions` rows
    /// `up` deleted are gone for good. Supported for development, not as a
    /// production downgrade path.
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Restore m00072's NOT NULL; shared-lifecycle NULLs go back to the nil
        // sentinel it introduced.
        manager
            .exec_stmt(
                Query::update()
                    .table(session::Entity)
                    .value(Alias::new("node_id"), Uuid::nil())
                    .and_where(Expr::col(Alias::new("node_id")).is_null())
                    .to_owned(),
            )
            .await?;
        if manager.get_database_backend() != DbBackend::Sqlite {
            manager
                .alter_table(
                    Table::alter()
                        .table(session::Entity)
                        .modify_column(ColumnDef::new(Alias::new("node_id")).uuid().not_null())
                        .to_owned(),
                )
                .await?;
        }
        manager
            .alter_table(
                Table::alter()
                    .table(session::Entity)
                    .drop_column(Alias::new("user_session_id"))
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(user_session::Entity).to_owned())
            .await
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::ActiveValue::Set;
    use sea_orm::{ColumnTrait, Database, EntityTrait, PaginatorTrait, QueryFilter};
    use sea_orm_migration::MigratorTrait;
    use sea_orm_migration::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
    use warpgate_db_entities::{Recording, TargetSession, UserSession};

    use crate::Migrator;

    /// The `sessions` schema as it stood before this migration, for writing
    /// pre-migration rows.
    mod legacy_session {
        use sea_orm::entity::prelude::*;
        use time::OffsetDateTime;
        use uuid::Uuid;

        #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
        #[sea_orm(table_name = "sessions")]
        pub struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub id: Uuid,
            pub target_snapshot: Option<String>,
            pub username: Option<String>,
            pub user_id: Option<Uuid>,
            pub target_id: Option<Uuid>,
            pub remote_address: String,
            pub started: OffsetDateTime,
            pub ended: Option<OffsetDateTime>,
            pub ticket_id: Option<Uuid>,
            pub protocol: String,
            pub node_id: Uuid,
        }

        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}

        impl ActiveModelBehavior for ActiveModel {}
    }

    fn legacy_row(id: Uuid, target_id: Option<Uuid>) -> legacy_session::ActiveModel {
        legacy_session::ActiveModel {
            id: Set(id),
            target_snapshot: Set(target_id.map(|_| r#"{"name":"web"}"#.into())),
            username: Set(Some("alice".into())),
            user_id: Set(Some(Uuid::new_v4())),
            target_id: Set(target_id),
            remote_address: Set("127.0.0.1:22".into()),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            ticket_id: Set(None),
            protocol: Set("SSH".into()),
            node_id: Set(Uuid::new_v4()),
        }
    }

    #[tokio::test]
    async fn backfills_existing_sessions_as_one_to_one_parents() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, Some(79)).await.unwrap();

        let id = Uuid::new_v4();
        let target_id = Uuid::new_v4();
        legacy_session::Entity::insert(legacy_row(id, Some(target_id)))
            .exec_without_returning(&db)
            .await
            .unwrap();

        Migrator::up(&db, None).await.unwrap();

        let parent = UserSession::Entity::find_by_id(warpgate_common::UserSessionId(id))
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        let child = TargetSession::Entity::find_by_id(warpgate_common::TargetSessionId(id))
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(parent.username.as_deref(), Some("alice"));
        assert_eq!(parent.remote_address, "127.0.0.1:22");
        assert_eq!(parent.protocol, "SSH");
        assert_eq!(child.user_session_id.0, id);
        assert_eq!(child.target_id, target_id);

        let second_id = Uuid::new_v4();
        TargetSession::Entity::insert(TargetSession::ActiveModel {
            id: Set(warpgate_common::TargetSessionId(second_id)),
            user_session_id: Set(warpgate_common::UserSessionId(id)),
            target_snapshot: Set(r#"{"name":"web"}"#.into()),
            target_id: Set(Uuid::new_v4()),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            ticket_id: Set(None),
            node_id: Set(parent.node_id),
        })
        .exec_without_returning(&db)
        .await
        .unwrap();
        assert_eq!(
            TargetSession::Entity::find()
                .filter(TargetSession::Column::UserSessionId.eq(id))
                .count(&db)
                .await
                .unwrap(),
            2
        );
    }

    #[test]
    fn target_id_recovery_prefers_embedded_id_then_name() {
        let target_id = Uuid::new_v4();
        let embedded = Uuid::new_v4();
        let targets = std::collections::HashMap::from([("web".to_string(), target_id)]);

        assert_eq!(
            super::recover_target_id(&format!(r#"{{"name":"web","id":"{embedded}"}}"#), &targets),
            embedded
        );
        assert_eq!(
            super::recover_target_id(&format!(r#"{{"name":"gone","id":"{embedded}"}}"#), &targets),
            embedded
        );
        assert_eq!(
            super::recover_target_id(r#"{"name":"web"}"#, &targets),
            target_id
        );
        assert_eq!(super::recover_target_id("not json", &targets), Uuid::nil());
    }

    /// Sessions predating m00077 carry a `target_snapshot` but a NULL
    /// `target_id` — they connected, and the migration must keep them and
    /// their recordings.
    #[tokio::test]
    async fn a_pre_target_id_column_row_keeps_its_history() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, Some(79)).await.unwrap();

        let target_id = Uuid::new_v4();
        warpgate_db_entities::Target::Entity::insert(warpgate_db_entities::Target::ActiveModel {
            id: Set(target_id),
            name: Set("web".into()),
            description: Set(String::new()),
            kind: Set(warpgate_db_entities::Target::TargetKind::Http),
            options: Set(serde_json::json!({})),
            rate_limit_bytes_per_second: Set(None),
            group_id: Set(None),
            ticket_max_duration_seconds: Set(None),
            ticket_requests_disabled: Set(false),
            ticket_require_approval: Set(false),
            ticket_max_uses: Set(None),
        })
        .exec_without_returning(&db)
        .await
        .unwrap();

        let resolved_id = Uuid::new_v4();
        let mut row = legacy_row(resolved_id, None);
        row.target_snapshot = Set(Some(r#"{"name":"web"}"#.into()));
        legacy_session::Entity::insert(row)
            .exec_without_returning(&db)
            .await
            .unwrap();

        let embedded = Uuid::new_v4();
        let renamed_id = Uuid::new_v4();
        let mut row = legacy_row(renamed_id, None);
        row.target_snapshot = Set(Some(format!(r#"{{"name":"gone","id":"{embedded}"}}"#)));
        legacy_session::Entity::insert(row)
            .exec_without_returning(&db)
            .await
            .unwrap();

        Recording::Entity::insert(Recording::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set("terminal".into()),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            session_id: Set(warpgate_common::TargetSessionId(resolved_id)),
            kind: Set(Recording::RecordingKind::Terminal),
            metadata: Set("{}".into()),
            generation: Set(1),
        })
        .exec_without_returning(&db)
        .await
        .unwrap();

        Migrator::up(&db, None).await.unwrap();

        let child =
            TargetSession::Entity::find_by_id(warpgate_common::TargetSessionId(resolved_id))
                .one(&db)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(child.target_id, target_id);
        let child = TargetSession::Entity::find_by_id(warpgate_common::TargetSessionId(renamed_id))
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(child.target_id, embedded);
        assert_eq!(
            Recording::Entity::find()
                .filter(Recording::Column::SessionId.eq(resolved_id))
                .count(&db)
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn a_targetless_session_becomes_a_user_session_only() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, Some(79)).await.unwrap();

        let id = Uuid::new_v4();
        legacy_session::Entity::insert(legacy_row(id, None))
            .exec_without_returning(&db)
            .await
            .unwrap();
        Recording::Entity::insert(Recording::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set("terminal".into()),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            session_id: Set(warpgate_common::TargetSessionId(id)),
            kind: Set(Recording::RecordingKind::Terminal),
            metadata: Set("{}".into()),
            generation: Set(1),
        })
        .exec_without_returning(&db)
        .await
        .unwrap();

        Migrator::up(&db, None).await.unwrap();

        assert!(
            UserSession::Entity::find_by_id(warpgate_common::UserSessionId(id))
                .one(&db)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            TargetSession::Entity::find_by_id(warpgate_common::TargetSessionId(id))
                .one(&db)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            Recording::Entity::find()
                .filter(Recording::Column::SessionId.eq(id))
                .count(&db)
                .await
                .unwrap(),
            0
        );
    }
}
