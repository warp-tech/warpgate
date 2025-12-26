use sea_orm_migration::prelude::*;

use super::m00021_ldap_server::ldap_server;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ldap_server::Entity)
                    .add_column_if_not_exists(
                        ColumnDef::new(Alias::new("ssh_key_attribute"))
                            .string()
                            .not_null()
                            .default("sshPublicKey"),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ldap_server::Entity)
                    .drop_column(Alias::new("ssh_key_attribute"))
                    .to_owned(),
            )
            .await
    }
}
