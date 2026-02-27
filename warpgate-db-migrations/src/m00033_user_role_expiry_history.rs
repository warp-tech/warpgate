use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add expiry columns to user_roles
        // Note: SQLite doesn't support non-constant defaults in ALTER TABLE ADD COLUMN,
        // so we add granted_at as nullable first, then update existing rows with a fixed timestamp
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("user_roles"))
                    .add_column(
                        ColumnDef::new(Alias::new("granted_at")).timestamp().null(), // Start as nullable
                    )
                    .to_owned(),
            )
            .await?;

        // Set existing rows to a fixed timestamp (migration time)
        // Using raw SQL for SQLite compatibility
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE user_roles SET granted_at = datetime('now') WHERE granted_at IS NULL",
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("user_roles"))
                    .add_column(ColumnDef::new(Alias::new("granted_by")).uuid().null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("user_roles"))
                    .add_column(ColumnDef::new(Alias::new("expires_at")).timestamp().null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("user_roles"))
                    .add_column(ColumnDef::new(Alias::new("revoked_at")).timestamp().null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("user_roles"))
                    .add_column(ColumnDef::new(Alias::new("revoked_by")).uuid().null())
                    .to_owned(),
            )
            .await?;

        // Create history table
        // Note: For CREATE TABLE, we can use a string default for SQLite
        manager
            .create_table(
                Table::create()
                    .table(Alias::new("user_role_history"))
                    .col(
                        ColumnDef::new(Alias::new("id"))
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Alias::new("user_id")).uuid().not_null())
                    .col(ColumnDef::new(Alias::new("role_id")).uuid().not_null())
                    .col(
                        ColumnDef::new(Alias::new("action"))
                            .string_len(20)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("occurred_at"))
                            .timestamp()
                            .not_null(),
                    )
                    .col(ColumnDef::new(Alias::new("actor_id")).uuid().null())
                    .col(
                        ColumnDef::new(Alias::new("details"))
                            .json_binary()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Create indexes
        manager
            .create_index(
                Index::create()
                    .table(Alias::new("user_role_history"))
                    .name("idx_urh_user")
                    .col(Alias::new("user_id"))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(Alias::new("user_role_history"))
                    .name("idx_urh_role")
                    .col(Alias::new("role_id"))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(Alias::new("user_role_history"))
                    .name("idx_urh_occurred")
                    .col(Alias::new("occurred_at"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(Alias::new("user_role_history"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("user_roles"))
                    .drop_column(Alias::new("granted_at"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("user_roles"))
                    .drop_column(Alias::new("granted_by"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("user_roles"))
                    .drop_column(Alias::new("expires_at"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("user_roles"))
                    .drop_column(Alias::new("revoked_at"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("user_roles"))
                    .drop_column(Alias::new("revoked_by"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
