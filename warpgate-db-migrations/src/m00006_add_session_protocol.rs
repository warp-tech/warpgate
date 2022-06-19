use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00006_add_session_protocol"
    }
}

use crate::m00002_create_session::session;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(session::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("protocol"))
                            .string()
                            .not_null()
                            .default("SSH"),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(session::Entity)
                    .drop_column(Alias::new("protocol"))
                    .to_owned(),
            )
            .await
    }
}
