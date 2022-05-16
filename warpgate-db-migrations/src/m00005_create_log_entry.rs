use sea_schema::migration::sea_orm::Schema;
use sea_schema::migration::sea_query::*;
use sea_schema::migration::*;

pub mod log_entry {
    use chrono::{DateTime, Utc};
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "log")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub text: String,
        pub timestamp: DateTime<Utc>,
        pub session_id: Uuid,
        pub username: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00005_create_log_entry"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let builder = manager.get_database_backend();
        let schema = Schema::new(builder);
        manager
            .create_table(schema.create_table_from_entity(log_entry::Entity))
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(log_entry::Entity)
                    .name("log_entry__timestamp_session_id")
                    .col(log_entry::Column::Timestamp)
                    .col(log_entry::Column::SessionId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(log_entry::Entity)
                    .name("log_entry__session_id")
                    .col(log_entry::Column::SessionId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(log_entry::Entity)
                    .name("log_entry__username")
                    .col(log_entry::Column::Username)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(log_entry::Entity).to_owned())
            .await
    }
}
