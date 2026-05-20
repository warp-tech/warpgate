use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00037_allowed_ip_range"
    }
}

use crate::m00008_users::user;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(user::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("allowed_ip_ranges"))
                            .json()
                            .default("null"),
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
                    .table(user::Entity)
                    .drop_column(Alias::new("allowed_ip_ranges"))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
