use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add sftp_permission_mode column to parameters table
        // Values: "strict" (default) or "permissive"
        // - strict: Shell/exec/forwarding blocked when SFTP restrictions are active
        // - permissive: SFTP enforced but shell/exec/forwarding still allowed
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("parameters"))
                    .add_column(
                        ColumnDef::new(Alias::new("sftp_permission_mode"))
                            .string()
                            .not_null()
                            .default("strict"),
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
                    .table(Alias::new("parameters"))
                    .drop_column(Alias::new("sftp_permission_mode"))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
