use sea_orm::Schema;
use sea_orm_migration::prelude::*;

pub mod http_session {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "http_sessions")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub expires: Option<OffsetDateTime>,
        #[sea_orm(column_type = "Text")]
        pub data: String,
        pub updated: OffsetDateTime,
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
            .create_table(schema.create_table_from_entity(http_session::Entity))
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_http_sessions_expires")
                    .table(http_session::Entity)
                    .col(http_session::Column::Expires)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(http_session::Entity).to_owned())
            .await?;
        Ok(())
    }
}
