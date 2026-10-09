use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::m00010_parameters::parameters;

/// Custom logo shown in place of the Warpgate brand, stored as a `data:image/…`
/// URL. `NULL` means "use the default brand".
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let mut column = ColumnDef::new(Alias::new("logo"));
        // MySQL's TEXT stops at 64 KB, below the 4 MiB the API accepts.
        if manager.get_database_backend() == DbBackend::MySql {
            column.custom(Alias::new("MEDIUMTEXT"));
        } else {
            column.text();
        }
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .add_column(column.null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .drop_column(Alias::new("logo"))
                    .to_owned(),
            )
            .await
    }
}
