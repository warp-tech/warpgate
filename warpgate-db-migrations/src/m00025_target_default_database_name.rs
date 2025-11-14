use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00025_target_default_database_name"
    }
}

use crate::m00007_targets_and_roles::target;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(target::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("default_database_name"))
                            .string()
                            .null(),
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
                    .table(target::Entity)
                    .drop_column(Alias::new("default_database_name"))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

