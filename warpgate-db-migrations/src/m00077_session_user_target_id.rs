use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // SQLite only supports one ADD COLUMN per ALTER TABLE
        for column in ["user_id", "target_id"] {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("sessions"))
                        .add_column(ColumnDef::new(Alias::new(column)).uuid().null())
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for column in ["user_id", "target_id"] {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("sessions"))
                        .drop_column(Alias::new(column))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
