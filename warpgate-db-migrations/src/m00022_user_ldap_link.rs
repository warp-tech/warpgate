use sea_orm_migration::prelude::*;

pub struct Migration;

pub mod user {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "users")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub username: String,
        pub credential_policy: serde_json::Value,
        #[sea_orm(column_type = "Text")]
        pub description: String,
        pub rate_limit_bytes_per_second: Option<i64>,
        pub ldap_server_id: Option<Uuid>,
        #[sea_orm(column_type = "Text", nullable)]
        pub ldap_object_uuid: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

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
                    .table(user::Entity)
                    .add_column(ColumnDef::new(user::Column::LdapServerId).uuid().null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(user::Entity)
                    .add_column(ColumnDef::new(user::Column::LdapObjectUuid).text().null())
                    .to_owned(),
            )
            .await?;

        // Add index on ldap_server_id for foreign key-like lookups
        manager
            .create_index(
                Index::create()
                    .name("idx_users_ldap_server_id")
                    .table(user::Entity)
                    .col(user::Column::LdapServerId)
                    .to_owned(),
            )
            .await?;

        // Add unique index on (ldap_server_id, ldap_object_uuid) to ensure no duplicates
        manager
            .create_index(
                Index::create()
                    .name("idx_users_ldap_unique")
                    .table(user::Entity)
                    .col(user::Column::LdapServerId)
                    .col(user::Column::LdapObjectUuid)
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
                    .table(user::Entity)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_users_ldap_server_id")
                    .table(user::Entity)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(user::Entity)
                    .drop_column(user::Column::LdapObjectUuid)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(user::Entity)
                    .drop_column(user::Column::LdapServerId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
