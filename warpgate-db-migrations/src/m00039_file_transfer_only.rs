use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add file_transfer_only column to roles table.
        // When true, users with this role can ONLY use SFTP — shell, exec,
        // and port forwarding are blocked regardless of sftp_permission_mode.
        // Default: false (backward compatible — no behavior change for existing roles).
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("roles"))
                    .add_column(
                        ColumnDef::new(Alias::new("file_transfer_only"))
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;

        // Add nullable override on target_roles table.
        // NULL = inherit from role default, true/false = explicit override for this target.
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("target_roles"))
                    .add_column(
                        ColumnDef::new(Alias::new("file_transfer_only"))
                            .boolean()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("target_roles"))
                    .drop_column(Alias::new("file_transfer_only"))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("roles"))
                    .drop_column(Alias::new("file_transfer_only"))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
