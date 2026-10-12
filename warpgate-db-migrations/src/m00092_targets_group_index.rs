use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

const INDEX_NAME: &str = "idx_targets_group_id_name";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Target lists are filtered by group and ordered by name within it.
        manager
            .create_index(
                Index::create()
                    .name(INDEX_NAME)
                    .table(Alias::new("targets"))
                    .col(Alias::new("group_id"))
                    .col(Alias::new("name"))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name(INDEX_NAME)
                    .table(Alias::new("targets"))
                    .to_owned(),
            )
            .await
    }
}
