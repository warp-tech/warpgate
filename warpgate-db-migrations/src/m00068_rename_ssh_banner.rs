use sea_orm_migration::prelude::*;

use crate::m00010_parameters::parameters;

/// The login banner is now shown over every protocol, not just SSH, so
/// `ssh_banner` is renamed to `banner`. Renaming preserves the admin's
/// existing value.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .rename_column(Alias::new("ssh_banner"), Alias::new("banner"))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .rename_column(Alias::new("banner"), Alias::new("ssh_banner"))
                    .to_owned(),
            )
            .await
    }
}
