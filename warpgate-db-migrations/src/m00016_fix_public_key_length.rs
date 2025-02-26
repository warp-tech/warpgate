use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

/// The original column type was `String` which defaults to VARCHAR(255) on MySQL
pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00016_fix_public_key_length"
    }
}

use crate::m00009_credential_models::public_key_credential;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let connection = manager.get_connection();
        if connection.get_database_backend() != DbBackend::Sqlite {
            manager
                .alter_table(
                    Table::alter()
                        .table(public_key_credential::Entity)
                        .modify_column(ColumnDef::new(Alias::new("openssh_public_key")).text())
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let connection = manager.get_connection();
        if connection.get_database_backend() != DbBackend::Sqlite {
            manager
                .alter_table(
                    Table::alter()
                        .table(public_key_credential::Entity)
                        .modify_column(ColumnDef::new(Alias::new("openssh_public_key")).string())
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
