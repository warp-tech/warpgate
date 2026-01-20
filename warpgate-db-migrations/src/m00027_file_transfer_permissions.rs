use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add file transfer permission columns to target_roles
        // SQLite doesn't support multiple ALTER TABLE operations in one statement,
        // so we run each column addition separately

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("target_roles"))
                    .add_column(
                        ColumnDef::new(Alias::new("allow_file_upload"))
                            .boolean()
                            .not_null()
                            .default(true), // backward compat
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("target_roles"))
                    .add_column(
                        ColumnDef::new(Alias::new("allow_file_download"))
                            .boolean()
                            .not_null()
                            .default(true), // backward compat
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("target_roles"))
                    .add_column(
                        ColumnDef::new(Alias::new("allowed_paths"))
                            .json_binary()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("target_roles"))
                    .add_column(
                        ColumnDef::new(Alias::new("blocked_extensions"))
                            .json_binary()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("target_roles"))
                    .add_column(
                        ColumnDef::new(Alias::new("max_file_size"))
                            .big_integer()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // SQLite doesn't support DROP COLUMN directly in older versions
        // For modern SQLite (3.35.0+), individual drops are supported
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("target_roles"))
                    .drop_column(Alias::new("allow_file_upload"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("target_roles"))
                    .drop_column(Alias::new("allow_file_download"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("target_roles"))
                    .drop_column(Alias::new("allowed_paths"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("target_roles"))
                    .drop_column(Alias::new("blocked_extensions"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("target_roles"))
                    .drop_column(Alias::new("max_file_size"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
