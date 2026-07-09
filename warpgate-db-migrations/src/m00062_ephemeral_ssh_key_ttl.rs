use sea_orm_migration::prelude::*;

use crate::m00008_users::user;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(user::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("ephemeral_ssh_key_ttl_seconds"))
                            .big_integer()
                            .null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(user::Entity)
                    .drop_column(Alias::new("ephemeral_ssh_key_ttl_seconds"))
                    .to_owned(),
            )
            .await
    }
}
