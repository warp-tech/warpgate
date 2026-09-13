use sea_orm::Schema;
use sea_orm_migration::prelude::*;

pub mod secret_backend {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "secret_backends")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        #[sea_orm(unique)]
        pub name: String,
        pub backend_type: String,
        #[sea_orm(column_type = "Text")]
        pub address: String,
        pub namespace: Option<String>,
        pub auth_method: String,
        pub auth_mount: String,
        #[sea_orm(column_type = "Text", nullable)]
        pub token: Option<String>,
        pub app_role_id: Option<String>,
        #[sea_orm(column_type = "Text", nullable)]
        pub app_role_secret_id: Option<String>,
        pub kubernetes_role: Option<String>,
        pub tls_skip_verify: bool,
        #[sea_orm(column_type = "Text")]
        pub allowed_paths: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let schema = Schema::new(manager.get_database_backend());
        manager
            .create_table(schema.create_table_from_entity(secret_backend::Entity))
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(secret_backend::Entity).to_owned())
            .await
    }
}
