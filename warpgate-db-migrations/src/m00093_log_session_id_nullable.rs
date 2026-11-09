use sea_orm::{
    ConnectionTrait, DatabaseTransaction, DbBackend, StatementBuilder, TransactionTrait,
};
use sea_orm_migration::prelude::*;

/// Audit events raised outside a user session (API-token requests) carry no
/// session id, so `log.session_id` becomes nullable.
#[derive(DeriveMigrationName)]
pub struct Migration;

const LOG: &str = "log";
const LOG_TMP: &str = "log_new";

/// `(index name, columns)` for every index on `log`. SQLite drops them along
/// with the table it rebuilds, so they are recreated on the replacement.
const INDEXES: &[(&str, &[&str])] = &[
    (
        "log_entry__timestamp_session_id",
        &["timestamp", "session_id"],
    ),
    ("log_entry__session_id", &["session_id"]),
    ("log_entry__username", &["username"]),
    ("log_target_timestamp", &["target", "timestamp"]),
    ("log_related_users", &["related_users"]),
    ("log_related_access_roles", &["related_access_roles"]),
    ("log_related_admin_roles", &["related_admin_roles"]),
];

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() != DbBackend::Sqlite {
            return manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new(LOG))
                        .modify_column(ColumnDef::new(Alias::new("session_id")).uuid().null())
                        .to_owned(),
                )
                .await;
        }

        // SQLite enforces NOT NULL but cannot drop it in place, so the table is
        // rebuilt. Kept on one connection: sea-orm only wraps migrations in a
        // transaction on PostgreSQL, and pooled SQLite connections holding an
        // older schema snapshot reject the statements otherwise.
        let db = manager.get_connection().begin().await?;

        exec(
            &db,
            &Table::create()
                .table(Alias::new(LOG_TMP))
                .col(
                    ColumnDef::new(Alias::new("id"))
                        .uuid()
                        .not_null()
                        .primary_key(),
                )
                .col(ColumnDef::new(Alias::new("text")).text().not_null())
                .col(ColumnDef::new(Alias::new("values")).json().not_null())
                .col(
                    ColumnDef::new(Alias::new("timestamp"))
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .col(ColumnDef::new(Alias::new("session_id")).uuid().null())
                .col(ColumnDef::new(Alias::new("username")).string().null())
                .col(
                    ColumnDef::new(Alias::new("target"))
                        .string()
                        .not_null()
                        .default("warpgate"),
                )
                .col(ColumnDef::new(Alias::new("related_users")).string().null())
                .col(
                    ColumnDef::new(Alias::new("related_access_roles"))
                        .string()
                        .null(),
                )
                .col(
                    ColumnDef::new(Alias::new("related_admin_roles"))
                        .string()
                        .null(),
                )
                .to_owned(),
        )
        .await?;

        let columns = r#""id", "text", "values", "timestamp", "session_id", "username", "target", "related_users", "related_access_roles", "related_admin_roles""#;
        db.execute_unprepared(&format!(
            r#"INSERT INTO "{LOG_TMP}" ({columns}) SELECT {columns} FROM "{LOG}""#
        ))
        .await?;

        exec(&db, &Table::drop().table(Alias::new(LOG)).to_owned()).await?;
        exec(
            &db,
            &Table::rename()
                .table(Alias::new(LOG_TMP), Alias::new(LOG))
                .to_owned(),
        )
        .await?;

        for (name, cols) in INDEXES {
            let mut index = Index::create();
            index.name(*name).table(Alias::new(LOG));
            for col in *cols {
                index.col(Alias::new(*col));
            }
            exec(&db, &index).await?;
        }

        db.commit().await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .exec_stmt(
                Query::delete()
                    .from_table(Alias::new(LOG))
                    .and_where(Expr::col(Alias::new("session_id")).is_null())
                    .to_owned(),
            )
            .await?;

        // SQLite keeps the column nullable; with the NULL rows gone it holds
        // what the older schema expects.
        if manager.get_database_backend() != DbBackend::Sqlite {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new(LOG))
                        .modify_column(ColumnDef::new(Alias::new("session_id")).uuid().not_null())
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}

async fn exec<S: StatementBuilder>(db: &DatabaseTransaction, stmt: &S) -> Result<(), DbErr> {
    let statement = db.get_database_backend().build(stmt);
    db.execute(statement).await?;
    Ok(())
}
