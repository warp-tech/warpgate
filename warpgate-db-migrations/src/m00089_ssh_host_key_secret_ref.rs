use sea_orm_migration::prelude::*;

use crate::m00010_parameters::parameters;

/// A `secret://backend/mount/path` reference to a secret-backend KV entry holding
/// the SSH host keys. Null means the keys stored in the parameters row are used.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("ssh_host_key_secret_ref"))
                            .text()
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
                    .table(parameters::Entity)
                    .drop_column(Alias::new("ssh_host_key_secret_ref"))
                    .to_owned(),
            )
            .await
    }
}
