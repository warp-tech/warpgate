use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // SQLite doesn't support ALTER COLUMN, so we need to:
        // 1. Add new nullable columns
        // 2. Copy data (convert TRUE to NULL for inheritance, keep FALSE as explicit deny)
        // 3. Drop old columns
        // 4. Rename new columns

        // Add new nullable upload column
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("target_roles"))
                    .add_column(
                        ColumnDef::new(Alias::new("allow_file_upload_v2"))
                            .boolean()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Add new nullable download column
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("target_roles"))
                    .add_column(
                        ColumnDef::new(Alias::new("allow_file_download_v2"))
                            .boolean()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Migrate data: only copy FALSE values (explicit denials)
        // TRUE values become NULL (inherit from role)
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE target_roles SET allow_file_upload_v2 = CASE WHEN allow_file_upload = 0 THEN 0 ELSE NULL END",
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE target_roles SET allow_file_download_v2 = CASE WHEN allow_file_download = 0 THEN 0 ELSE NULL END",
            )
            .await?;

        // Drop old columns and rename new ones
        // Note: SQLite 3.35.0+ supports DROP COLUMN
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
                    .rename_column(
                        Alias::new("allow_file_upload_v2"),
                        Alias::new("allow_file_upload"),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("target_roles"))
                    .rename_column(
                        Alias::new("allow_file_download_v2"),
                        Alias::new("allow_file_download"),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Reverse: make columns non-nullable with default true
        // Add new non-nullable columns
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("target_roles"))
                    .add_column(
                        ColumnDef::new(Alias::new("allow_file_upload_v2"))
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("target_roles"))
                    .add_column(
                        ColumnDef::new(Alias::new("allow_file_download_v2"))
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .to_owned(),
            )
            .await?;

        // Copy data: NULL becomes TRUE, FALSE stays FALSE
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE target_roles SET allow_file_upload_v2 = COALESCE(allow_file_upload, 1)",
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE target_roles SET allow_file_download_v2 = COALESCE(allow_file_download, 1)",
            )
            .await?;

        // Drop and rename
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
                    .rename_column(
                        Alias::new("allow_file_upload_v2"),
                        Alias::new("allow_file_upload"),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("target_roles"))
                    .rename_column(
                        Alias::new("allow_file_download_v2"),
                        Alias::new("allow_file_download"),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
