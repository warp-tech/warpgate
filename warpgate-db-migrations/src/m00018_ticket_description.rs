use sea_orm_migration::prelude::*;

use crate::m00001_create_ticket::ticket;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00018_ticket_description"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ticket::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("description"))
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ticket::Entity)
                    .drop_column(Alias::new("description"))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
