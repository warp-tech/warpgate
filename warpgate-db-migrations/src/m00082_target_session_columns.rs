use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::m00002_create_session::session;

/// Login-identity columns that m00080 moved from `sessions` to
/// `user_sessions`.
const MOVED_COLUMNS: [&str; 4] = ["username", "user_id", "remote_address", "protocol"];

/// The schema tightening for the user/target session split, kept apart from
/// m00080's data migration: these columns can only be tightened once that has
/// left no NULLs behind. Ends by renaming `sessions` to `target_sessions`,
/// after every statement that refers to the old name.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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

        // SQLite cannot alter a column's nullability in place: m00080's
        // backfill and deletions leave no NULLs there, and the app always
        // writes these columns.
        if manager.get_database_backend() != DbBackend::Sqlite {
            manager
                .alter_table(
                    Table::alter()
                        .table(session::Entity)
                        .modify_column(
                            ColumnDef::new(Alias::new("user_session_id"))
                                .uuid()
                                .not_null(),
                        )
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
                        .modify_column(
                            ColumnDef::new(Alias::new("target_snapshot"))
                                .text()
                                .not_null(),
                        )
                        .to_owned(),
                )
                .await?;
        }

        // A target session is an access record: one row per (login, target).
        // m00080 pairs every pre-split row with a parent of its own id, so no
        // two existing rows share a parent and the index holds.
        manager
            .create_index(
                Index::create()
                    .name("idx_target_sessions_user_session_target")
                    .table(session::Entity)
                    .col(Alias::new("user_session_id"))
                    .col(Alias::new("target_id"))
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .rename_table(
                Table::rename()
                    .table(Alias::new("sessions"), Alias::new("target_sessions"))
                    .to_owned(),
            )
            .await
    }

    /// Restores the schema, not the contents: the dropped columns come back
    /// empty, since what they held now lives in `user_sessions`. Supported for
    /// development, not as a production downgrade path.
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .rename_table(
                Table::rename()
                    .table(Alias::new("target_sessions"), Alias::new("sessions"))
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_target_sessions_user_session_target")
                    .table(session::Entity)
                    .to_owned(),
            )
            .await?;

        if manager.get_database_backend() != DbBackend::Sqlite {
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
            manager
                .alter_table(
                    Table::alter()
                        .table(session::Entity)
                        .modify_column(ColumnDef::new(Alias::new("user_session_id")).uuid().null())
                        .to_owned(),
                )
                .await?;
        }

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
            .await
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::ActiveValue::Set;
    use sea_orm::{Database, EntityTrait, PaginatorTrait};
    use sea_orm_migration::MigratorTrait;
    use time::OffsetDateTime;
    use uuid::Uuid;
    use warpgate_common::{TargetSessionId, UserSessionId};
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
    use warpgate_db_entities::{Recording, TargetSession, UserSession};

    use crate::Migrator;

    async fn migrated_db() -> sea_orm::DatabaseConnection {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        db
    }

    fn access_row(user_session_id: Uuid, target_id: Uuid) -> TargetSession::ActiveModel {
        TargetSession::ActiveModel {
            id: Set(TargetSessionId(Uuid::new_v4())),
            user_session_id: Set(UserSessionId(user_session_id)),
            target_snapshot: Set(r#"{"name":"web"}"#.into()),
            target_id: Set(target_id),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            ticket_id: Set(None),
            node_id: Set(None),
        }
    }

    async fn user_session(db: &sea_orm::DatabaseConnection) -> Uuid {
        let id = Uuid::new_v4();
        UserSession::Entity::insert(UserSession::ActiveModel {
            id: Set(UserSessionId(id)),
            username: Set(Some("alice".into())),
            user_id: Set(Some(Uuid::new_v4())),
            remote_address: Set("127.0.0.1:1".into()),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            protocol: Set("HTTP".into()),
            node_id: Set(None),
            auth_state_node_id: Set(None),
        })
        .exec_without_returning(db)
        .await
        .unwrap();
        id
    }

    #[tokio::test]
    async fn one_access_row_per_login_and_target() {
        let db = migrated_db().await;
        let parent = user_session(&db).await;
        let target_id = Uuid::new_v4();

        TargetSession::Entity::insert(access_row(parent, target_id))
            .exec_without_returning(&db)
            .await
            .unwrap();
        TargetSession::Entity::insert(access_row(parent, target_id))
            .exec_without_returning(&db)
            .await
            .expect_err("the unique (user_session_id, target_id) index must reject a second row");
        TargetSession::Entity::insert(access_row(parent, Uuid::new_v4()))
            .exec_without_returning(&db)
            .await
            .unwrap();
    }

    /// The recordings foreign key must follow the table rename: a recording
    /// still resolves its session, and deleting the session still cascades.
    #[tokio::test]
    async fn recordings_follow_the_renamed_table() {
        let db = migrated_db().await;
        let parent = user_session(&db).await;
        let session_id = Uuid::new_v4();
        let mut row = access_row(parent, Uuid::new_v4());
        row.id = Set(TargetSessionId(session_id));
        TargetSession::Entity::insert(row)
            .exec_without_returning(&db)
            .await
            .unwrap();

        Recording::Entity::insert(Recording::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set("terminal".into()),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            session_id: Set(TargetSessionId(session_id)),
            kind: Set(Recording::RecordingKind::Terminal),
            metadata: Set(String::new()),
            generation: Set(3),
        })
        .exec_without_returning(&db)
        .await
        .unwrap();

        TargetSession::Entity::delete_by_id(TargetSessionId(session_id))
            .exec(&db)
            .await
            .unwrap();
        assert_eq!(Recording::Entity::find().count(&db).await.unwrap(), 0);
    }
}
