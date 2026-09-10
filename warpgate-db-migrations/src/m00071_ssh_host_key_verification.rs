use sea_orm::{ActiveEnum, ConnectionTrait};
use sea_orm_migration::prelude::*;
use warpgate_db_entities::Parameters::{SshHostKeyVerificationMode, get_config_migration_values};

use crate::m00010_parameters::parameters;

/// Host key verification moves out of the config file into the parameters row.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("ssh_host_key_verification"))
                            .string()
                            .not_null()
                            .default(SshHostKeyVerificationMode::Prompt.to_value()),
                    )
                    .to_owned(),
            )
            .await?;

        // Carry over the config-file setting of an existing install. A fresh
        // install has no row yet and is seeded by `Parameters::Entity::get`.
        let db = manager.get_connection();
        let backend = db.get_database_backend();
        let stmt = Query::update()
            .table(parameters::Entity)
            .value(
                Alias::new("ssh_host_key_verification"),
                get_config_migration_values()
                    .ssh_host_key_verification
                    .to_value(),
            )
            .to_owned();
        db.execute(backend.build(&stmt)).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .drop_column(Alias::new("ssh_host_key_verification"))
                    .to_owned(),
            )
            .await
    }
}
