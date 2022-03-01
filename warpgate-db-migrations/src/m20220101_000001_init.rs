use sea_schema::migration::sea_orm::Schema;
use sea_schema::migration::{sea_query::*, *};

use warpgate_db_entities::{Recording, Session};
pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20220101_000001_init"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let builder = manager.get_database_backend();
        let schema = Schema::new(builder);
        manager
            .create_table(schema.create_table_from_entity(Session::Entity))
            .await?;
        manager
            .create_table(schema.create_table_from_entity(Recording::Entity))
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(Recording::Entity)
                    .name("recording__unique__session_id__name")
                    .unique()
                    .col(Recording::Column::SessionId)
                    .col(Recording::Column::Name)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(Index::drop().name("recording__unique__session_id__name").to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Recording::Entity).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Session::Entity).to_owned())
            .await
    }
}
