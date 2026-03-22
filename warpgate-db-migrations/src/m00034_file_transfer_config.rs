use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add file_transfer_hash_threshold_bytes to parameters table
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("parameters"))
                    .add_column(
                        ColumnDef::new(Alias::new("file_transfer_hash_threshold_bytes"))
                            .big_integer()
                            .null()
                            .default(10485760), // 10MB default
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
                    .drop_column(Alias::new("file_transfer_hash_threshold_bytes"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
