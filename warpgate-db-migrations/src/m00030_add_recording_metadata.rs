use sea_orm::DbBackend;
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
        let mut col = ColumnDef::new(Alias::new("metadata")).text().to_owned();
        // MySQL does not allow defaults on TEXT columns; omit the default (NULL is equivalent here).
        if manager.get_database_backend() != DbBackend::MySql {
            col.default("null");
        }
        manager
            .alter_table(
                Table::alter()
                    .table(recording::Entity)
                    .add_column(col)
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
