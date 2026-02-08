use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("roles"))
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
                    .table(Alias::new("roles"))
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
                    .table(Alias::new("roles"))
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
                    .table(Alias::new("roles"))
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
                    .table(Alias::new("roles"))
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
        // Drop columns in reverse order
        for col in [
            "max_file_size",
            "blocked_extensions",
            "allowed_paths",
            "allow_file_download",
            "allow_file_upload",
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("roles"))
                        .drop_column(Alias::new(col))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
