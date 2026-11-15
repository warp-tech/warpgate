use sea_orm::Schema;
use sea_orm_migration::prelude::*;

pub mod command {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "commands")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub timestamp: OffsetDateTime,
        pub user_session_id: Uuid,
        pub username: Option<String>,
        #[sea_orm(column_type = "Text")]
        pub command: String,
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
            .create_table(schema.create_table_from_entity(command::Entity))
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_commands_timestamp")
                    .table(command::Entity)
                    .col(command::Column::Timestamp)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_commands_user_session_id")
                    .table(command::Entity)
                    .col(command::Column::UserSessionId)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(command::Entity).to_owned())
            .await
    }
}
