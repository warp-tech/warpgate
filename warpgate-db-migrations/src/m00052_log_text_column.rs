use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let connection = manager.get_connection();
        if connection.get_database_backend() != DbBackend::Sqlite {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("log"))
                        .modify_column(ColumnDef::new(Alias::new("text")).text().not_null())
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
                        .table(Alias::new("log"))
                        .modify_column(ColumnDef::new(Alias::new("text")).string().not_null())
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
