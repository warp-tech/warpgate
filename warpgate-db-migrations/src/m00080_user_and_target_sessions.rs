use sea_orm::{ConnectionTrait, DbBackend, Schema};
use sea_orm_migration::prelude::*;

use crate::m00002_create_session::session;

/// Login-identity columns that moved from `sessions` to `user_sessions`.
const MOVED_COLUMNS: [&str; 4] = ["username", "user_id", "remote_address", "protocol"];

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
        pub node_id: Uuid,
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
                 SELECT id, username, user_id, remote_address, started, ended, protocol, node_id \
                 FROM sessions",
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared("UPDATE sessions SET user_session_id = id")
            .await?;

        // A pre-split row that never reached a target was only ever a login:
        // it lives on as the `user_sessions` row created above, and its
        // `sessions` row goes. Recording rows are removed first — none should
        // exist for a session that never connected, but an orphan must not
        // survive its session.
        manager
            .get_connection()
            .execute_unprepared(
                "DELETE FROM recordings WHERE session_id IN \
                 (SELECT id FROM sessions WHERE target_id IS NULL OR target_snapshot IS NULL)",
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared(
                "DELETE FROM sessions WHERE target_id IS NULL OR target_snapshot IS NULL",
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_sessions_user_session_id")
                    .table(session::Entity)
                    .col(Alias::new("user_session_id"))
                    .to_owned(),
            )
            .await?;

        // The login-identity columns now live on `user_sessions`. SQLite
        // deployments are single-node, so no older node writes `sessions`
        // concurrently and the columns can be dropped outright. MySQL/Postgres
        // clusters keep them for one release so nodes still on the previous
        // version can read session rows during a rolling upgrade; their writes
        // are rejected once this has run, since they insert sessions without a
        // target or parent.
        //
        // SQLite cannot alter a column's nullability in place; the deletions
        // and backfill above leave no NULLs there, and the app always writes
        // these columns.
        if manager.get_database_backend() == DbBackend::Sqlite {
            for column in MOVED_COLUMNS {
                manager
                    .alter_table(
                        Table::alter()
                            .table(session::Entity)
                            .drop_column(Alias::new(column))
                            .to_owned(),
                    )
                    .await?;
            }
        } else {
            for column in ["remote_address", "protocol"] {
                manager
                    .alter_table(
                        Table::alter()
                            .table(session::Entity)
                            .modify_column(
                                ColumnDef::new(Alias::new(column))
                                    .string()
                                    .not_null()
                                    .default(""),
                            )
                            .to_owned(),
                    )
                    .await?;
            }
            manager
                .alter_table(
                    Table::alter()
                        .table(session::Entity)
                        .modify_column(ColumnDef::new(Alias::new("user_session_id")).uuid().not_null())
                        .to_owned(),
                )
                .await?;
            manager
                .alter_table(
                    Table::alter()
                        .table(session::Entity)
                        .modify_column(ColumnDef::new(Alias::new("target_id")).uuid().not_null())
                        .to_owned(),
                )
                .await?;
            manager
                .alter_table(
                    Table::alter()
                        .table(session::Entity)
                        // `text()`, matching the m00049 widening on these backends.
                        .modify_column(ColumnDef::new(Alias::new("target_snapshot")).text().not_null())
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DbBackend::Sqlite {
            manager
                .alter_table(
                    Table::alter()
                        .table(session::Entity)
                        .add_column(ColumnDef::new(Alias::new("username")).string().null())
                        .to_owned(),
                )
                .await?;
            manager
                .alter_table(
                    Table::alter()
                        .table(session::Entity)
                        .add_column(ColumnDef::new(Alias::new("user_id")).uuid().null())
                        .to_owned(),
                )
                .await?;
            manager
                .alter_table(
                    Table::alter()
                        .table(session::Entity)
                        .add_column(
                            ColumnDef::new(Alias::new("remote_address"))
                                .string()
                                .not_null()
                                .default(""),
                        )
                        .to_owned(),
                )
                .await?;
            manager
                .alter_table(
                    Table::alter()
                        .table(session::Entity)
                        .add_column(
                            ColumnDef::new(Alias::new("protocol"))
                                .string()
                                .not_null()
                                .default("SSH"),
                        )
                        .to_owned(),
                )
                .await?;
        } else {
            manager
                .alter_table(
                    Table::alter()
                        .table(session::Entity)
                        .modify_column(
                            ColumnDef::new(Alias::new("remote_address"))
                                .string()
                                .not_null(),
                        )
                        .to_owned(),
                )
                .await?;
            manager
                .alter_table(
                    Table::alter()
                        .table(session::Entity)
                        .modify_column(
                            ColumnDef::new(Alias::new("protocol"))
                                .string()
                                .not_null()
                                .default("SSH"),
                        )
                        .to_owned(),
                )
                .await?;
            manager
                .alter_table(
                    Table::alter()
                        .table(session::Entity)
                        .modify_column(ColumnDef::new(Alias::new("target_id")).uuid().null())
                        .to_owned(),
                )
                .await?;
            manager
                .alter_table(
                    Table::alter()
                        .table(session::Entity)
                        .modify_column(ColumnDef::new(Alias::new("target_snapshot")).text().null())
                        .to_owned(),
                )
                .await?;
        }
        manager
            .drop_index(
                Index::drop()
                    .name("idx_sessions_user_session_id")
                    .table(session::Entity)
                    .to_owned(),
            )
            .await?;
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

        let parent = UserSession::Entity::find_by_id(id)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        let child = TargetSession::Entity::find_by_id(id)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(parent.username.as_deref(), Some("alice"));
        assert_eq!(parent.remote_address, "127.0.0.1:22");
        assert_eq!(parent.protocol, "SSH");
        assert_eq!(child.user_session_id, id);
        assert_eq!(child.target_id, target_id);

        let second_id = Uuid::new_v4();
        TargetSession::Entity::insert(TargetSession::ActiveModel {
            id: Set(second_id),
            user_session_id: Set(id),
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
            session_id: Set(id),
            kind: Set(Recording::RecordingKind::Terminal),
            metadata: Set("{}".into()),
            generation: Set(1),
        })
        .exec_without_returning(&db)
        .await
        .unwrap();

        Migrator::up(&db, None).await.unwrap();

        assert!(
            UserSession::Entity::find_by_id(id)
                .one(&db)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            TargetSession::Entity::find_by_id(id)
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
