use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("log"))
                    .add_column_if_not_exists(
                        ColumnDef::new(Alias::new("target"))
                            .string()
                            .not_null()
                            .default("warpgate"),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(Alias::new("log"))
                    .name("log_target_timestamp")
                    .col(Alias::new("target"))
                    .col(Alias::new("timestamp"))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("log"))
                    .drop_column(Alias::new("target"))
                    .to_owned(),
            )
            .await
    }
}
