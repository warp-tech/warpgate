use sea_orm_migration::prelude::*;

use crate::m00010_parameters::parameters;

/// The `web_ssh_enabled` parameter now also gates the in-browser RDP/VNC desktop
/// clients, so it is renamed to `web_clients_enabled`. Renaming preserves the
/// admin's existing value.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .rename_column(
                        Alias::new("web_ssh_enabled"),
                        Alias::new("web_clients_enabled"),
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
                    .rename_column(
                        Alias::new("web_clients_enabled"),
                        Alias::new("web_ssh_enabled"),
                    )
                    .to_owned(),
            )
            .await
    }
}
