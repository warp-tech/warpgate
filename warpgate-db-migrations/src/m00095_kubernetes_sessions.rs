use sea_orm::Schema;
use sea_orm_migration::prelude::*;

pub mod kubernetes_session {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "kubernetes_sessions")]
    pub struct Model {
        #[sea_orm(
            primary_key,
            auto_increment = false,
            column_type = "String(StringLen::N(255))"
        )]
        pub key: String,
        pub user_session_id: Uuid,
        pub created: OffsetDateTime,
        pub target_session_id: Option<Uuid>,
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
            .create_table(schema.create_table_from_entity(kubernetes_session::Entity))
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_kubernetes_sessions_created")
                    .table(kubernetes_session::Entity)
                    .col(kubernetes_session::Column::Created)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(kubernetes_session::Entity).to_owned())
            .await
    }
}
