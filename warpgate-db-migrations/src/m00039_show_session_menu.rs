use sea_orm_migration::prelude::*;

use crate::m00010_parameters::parameters;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00037_show_session_menu"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("show_session_menu"))
                            .boolean()
                            .not_null()
                            .default(true),
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
                    .table(parameters::Entity)
                    .drop_column(Alias::new("show_session_menu"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
