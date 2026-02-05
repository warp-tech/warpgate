use sea_orm_migration::prelude::*;

pub struct Migration;
use super::m00003_create_recording::recording;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00030_add_recording_metadata"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(recording::Entity)
                    .add_column(ColumnDef::new(Alias::new("metadata")).text().default("null"))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(recording::Entity)
                    .drop_column(Alias::new("metadata"))
                    .to_owned(),
            )
            .await
    }
}
