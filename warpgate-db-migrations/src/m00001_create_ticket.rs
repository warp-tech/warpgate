use sea_orm::{DbBackend, Schema};
use sea_orm_migration::prelude::*;

pub mod ticket {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "tickets")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub secret: String,
        pub username: String,
        pub target: String,
        pub uses_left: Option<i16>,
        pub expiry: Option<DateTimeUtc>,
        pub created: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00001_create_ticket"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let builder = manager.get_database_backend();
        let schema = Schema::new(builder);

        manager
            .create_table(schema.create_table_from_entity(ticket::Entity))
            .await?;

        let connection = manager.get_connection();
        if connection.get_database_backend() == DbBackend::MySql {
            // https://github.com/warp-tech/warpgate/issues/857
            connection
                .execute_unprepared(
                    "ALTER TABLE `tickets` MODIFY COLUMN `expiry` TIMESTAMP NULL DEFAULT NULL",
                )
                .await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ticket::Entity).to_owned())
            .await
    }
}
