use sea_orm::Schema;
use sea_orm_migration::prelude::*;

pub mod ldap_server {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "ldap_servers")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        #[sea_orm(unique)]
        pub name: String,
        pub host: String,
        pub port: i32,
        pub bind_dn: String,
        pub bind_password: String,
        pub user_filter: String,
        pub base_dns: serde_json::Value,
        pub tls_mode: String,
        pub tls_verify: bool,
        pub enabled: bool,
        pub auto_link_sso_users: bool,
        #[sea_orm(column_type = "Text")]
        pub description: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00020_ldap_server"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let builder = manager.get_database_backend();
        let schema = Schema::new(builder);
        manager
            .create_table(schema.create_table_from_entity(ldap_server::Entity))
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ldap_server::Entity).to_owned())
            .await?;
        Ok(())
    }
}
