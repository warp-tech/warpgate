use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;
use warpgate_db_entities::Parameters::{
    RecordingsDiskConfig, RecordingsStorageConfig, get_config_migration_values,
};

use crate::helpers::string_default_value;
use crate::m00010_parameters::parameters;

#[derive(DeriveMigrationName)]
pub struct Migration;

async fn add_column(manager: &SchemaManager<'_>, column: ColumnDef) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(parameters::Entity)
                .add_column(column)
                .to_owned(),
        )
        .await
}

async fn drop_column(manager: &SchemaManager<'_>, name: &str) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(parameters::Entity)
                .drop_column(Alias::new(name))
                .to_owned(),
        )
        .await
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();

        #[allow(clippy::unwrap_used, reason = "serializing a constant enum can't fail")]
        let disk_default = serde_json::to_string(&RecordingsStorageConfig::default()).unwrap();

        add_column(
            manager,
            ColumnDef::new(Alias::new("recordings_enable"))
                .boolean()
                .not_null()
                .default(false)
                .to_owned(),
        )
        .await?;
        add_column(
            manager,
            ColumnDef::new(Alias::new("recordings_storage"))
                .text()
                .not_null()
                .default(string_default_value(backend, &disk_default))
                .to_owned(),
        )
        .await?;

        // Copy the config-file recordings settings (published by the process
        // before migrations run) into the existing parameters row. A fresh
        // install has no row yet and is seeded by `Parameters::Entity::get`.
        let values = get_config_migration_values();
        #[allow(clippy::unwrap_used, reason = "can't fail")]
        let stmt = Query::update()
            .table(parameters::Entity)
            .value(Alias::new("recordings_enable"), values.recordings_enable)
            .value(
                Alias::new("recordings_storage"),
                serde_json::to_string(&RecordingsStorageConfig::Disk(RecordingsDiskConfig {
                    path: values.recordings_path.clone(),
                }))
                .unwrap(),
            )
            .to_owned();
        manager
            .get_connection()
            .execute(backend.build(&stmt))
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        drop_column(manager, "recordings_storage").await?;
        drop_column(manager, "recordings_enable").await?;
        Ok(())
    }
}
