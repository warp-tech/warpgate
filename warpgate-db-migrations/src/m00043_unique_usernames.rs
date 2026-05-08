use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::ConnectionTrait;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = manager.get_database_backend();

        let child_tables = [
            "credentials_otp",
            "credentials_password",
            "credentials_public_key",
            "credentials_certificate",
            "credentials_sso",
            "api_tokens",
            "user_roles",
            "user_admin_roles",
            "tickets",
        ];

        // Delete all objects that reference duplicate users (via user_id FK),
        // keeping only the rows that belong to the user we will retain per username.
        // PostgreSQL's MIN() does not accept uuid, so we cast to text there.
        match backend {
            DbBackend::Postgres => {
                for table in &child_tables {
                    db.execute_unprepared(&format!(
                        "DELETE FROM {table} WHERE user_id::text NOT IN \
                         (SELECT MIN(id::text) FROM users GROUP BY username)"
                    ))
                    .await?;
                }
            }
            DbBackend::MySql | DbBackend::Sqlite => {
                for table in &child_tables {
                    db.execute_unprepared(&format!(
                        "DELETE FROM {table} WHERE user_id NOT IN \
                         (SELECT MIN(id) FROM users GROUP BY username)"
                    ))
                    .await?;
                }
            }
        }

        // Delete duplicate users, retaining the one with the lowest id per username.
        // MySQL does not allow a subquery to reference the same table being deleted
        // without an intermediate derived table, so we use a double-subquery there.
        // PostgreSQL requires a cast to text for MIN() on uuid.
        match backend {
            DbBackend::MySql => {
                db.execute_unprepared(
                    "DELETE FROM users WHERE id NOT IN \
                     (SELECT id FROM (SELECT MIN(id) AS id FROM users GROUP BY username) AS t)",
                )
                .await?;
            }
            DbBackend::Postgres => {
                db.execute_unprepared(
                    "DELETE FROM users WHERE id::text NOT IN \
                     (SELECT MIN(id::text) FROM users GROUP BY username)",
                )
                .await?;
            }
            DbBackend::Sqlite => {
                db.execute_unprepared(
                    "DELETE FROM users WHERE id NOT IN \
                     (SELECT MIN(id) FROM users GROUP BY username)",
                )
                .await?;
            }
        }

        // Add a unique index on username.  Using CREATE UNIQUE INDEX rather than
        // ALTER COLUMN so that the migration works on SQLite, which does not support
        // altering column constraints.
        manager
            .create_index(
                Index::create()
                    .name("users_username_unique")
                    .table(Alias::new("users"))
                    .col(Alias::new("username"))
                    .unique()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("users_username_unique")
                    .table(Alias::new("users"))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
