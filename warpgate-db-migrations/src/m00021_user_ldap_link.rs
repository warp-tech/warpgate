use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00021_user_ldap_link"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(User::Table)
                    .add_column(ColumnDef::new(User::LdapServerId).uuid().null())
                    .add_column(ColumnDef::new(User::LdapObjectUuid).text().null())
                    .to_owned(),
            )
            .await?;

        // Add index on ldap_server_id for foreign key-like lookups
        manager
            .create_index(
                Index::create()
                    .name("idx_users_ldap_server_id")
                    .table(User::Table)
                    .col(User::LdapServerId)
                    .to_owned(),
            )
            .await?;

        // Add unique index on (ldap_server_id, ldap_object_uuid) to ensure no duplicates
        manager
            .create_index(
                Index::create()
                    .name("idx_users_ldap_unique")
                    .table(User::Table)
                    .col(User::LdapServerId)
                    .col(User::LdapObjectUuid)
                    .unique()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_users_ldap_unique")
                    .table(User::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_users_ldap_server_id")
                    .table(User::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(User::Table)
                    .drop_column(User::LdapObjectUuid)
                    .drop_column(User::LdapServerId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(Iden)]
enum User {
    Table,
    LdapServerId,
    LdapObjectUuid,
}
