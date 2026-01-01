use sea_orm_migration::prelude::*;

use super::m00021_ldap_server::ldap_server;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00023_ldap_username_attribute"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ldap_server::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("username_attribute"))
                            .string()
                            .not_null()
                            .default("uid"),
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
                    .table(ldap_server::Entity)
                    .drop_column(Alias::new("username_attribute"))
                    .to_owned(),
            )
            .await
    }
}
