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
                        ColumnDef::new(Alias::new("granted_at")).timestamp().null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Set existing rows to a fixed timestamp (migration time)
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

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
