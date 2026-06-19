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
                        .table(Alias::new("sessions"))
                        .modify_column(ColumnDef::new(Alias::new("target_snapshot")).text().null())
                        .to_owned(),
                )
                .await?;
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("known_hosts"))
                        .modify_column(ColumnDef::new(Alias::new("key_base64")).text())
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
                        .table(Alias::new("sessions"))
                        .modify_column(
                            ColumnDef::new(Alias::new("target_snapshot"))
                                .string()
                                .null(),
                        )
                        .to_owned(),
                )
                .await?;
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("known_hosts"))
                        .modify_column(ColumnDef::new(Alias::new("key_base64")).string())
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
