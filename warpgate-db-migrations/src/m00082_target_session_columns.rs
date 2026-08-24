use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::m00002_create_session::session;

/// Login-identity columns that m00080 moved from `sessions` to
/// `user_sessions`.
const MOVED_COLUMNS: [&str; 4] = ["username", "user_id", "remote_address", "protocol"];

/// The schema tightening for the user/target session split, kept apart from
/// m00080's data migration: these columns can only be tightened once that has
/// left no NULLs behind, and separating the backend-specific DDL from the data
/// steps keeps each one's failure obvious.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // The login-identity columns now live on `user_sessions`. SQLite
        // deployments are single-node, so nothing else writes `sessions` and
        // the columns can be dropped outright. MySQL/Postgres keep them, since
        // dropping a column is the one change an in-flight query cannot
        // tolerate; they are dropped in a later release.
        //
        // SQLite cannot alter a column's nullability in place: m00080's
        // backfill and deletions leave no NULLs there, and the app always
        // writes these columns.
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
            return Ok(());
        }

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
            .await
    }

    /// Restores the columns' shape, not their contents: on SQLite the dropped
    /// columns come back empty, since what they held now lives in
    /// `user_sessions`. Supported for development, not as a production
    /// downgrade path.
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
            return manager
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
                .await;
        }

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
        manager
            .alter_table(
                Table::alter()
                    .table(session::Entity)
                    .modify_column(ColumnDef::new(Alias::new("user_session_id")).uuid().null())
                    .to_owned(),
            )
            .await
    }
}
