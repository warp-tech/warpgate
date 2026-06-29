use sea_orm_migration::prelude::*;

use crate::helpers::string_default_value;
use crate::m00010_parameters::parameters;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("ssh_banner"))
                            .text()
                            .not_null()
                            // MySQL rejects a literal DEFAULT on TEXT columns;
                            // string_default_value emits the parenthesised
                            // expression form it requires.
                            .default(string_default_value(backend, "")),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .drop_column(Alias::new("ssh_banner"))
                    .to_owned(),
            )
            .await
    }
}
