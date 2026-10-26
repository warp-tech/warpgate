use sea_orm::Schema;
use sea_orm_migration::prelude::*;

use crate::helpers::string_default_value;
use crate::m00010_parameters::parameters;

const SECRET_COLUMNS: [&str; 2] = ["slack_bot_token", "slack_signing_secret"];
const OPTIONAL_COLUMNS: [&str; 2] = ["slack_sso_provider", "slack_channel"];

pub mod slack_approval_message {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "slack_approval_messages")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub session_id: Uuid,
        pub target: String,
        pub request_started: OffsetDateTime,
        pub node_id: Uuid,
        pub channel: String,
        pub ts: String,
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
        let backend = manager.get_database_backend();
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("slack_enabled"))
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;
        for column in SECRET_COLUMNS {
            manager
                .alter_table(
                    Table::alter()
                        .table(parameters::Entity)
                        .add_column(
                            ColumnDef::new(Alias::new(column))
                                .text()
                                .not_null()
                                .default(string_default_value(backend, "")),
                        )
                        .to_owned(),
                )
                .await?;
        }
        for column in OPTIONAL_COLUMNS {
            manager
                .alter_table(
                    Table::alter()
                        .table(parameters::Entity)
                        .add_column(ColumnDef::new(Alias::new(column)).text().null())
                        .to_owned(),
                )
                .await?;
        }

        let schema = Schema::new(backend);
        manager
            .create_table(schema.create_table_from_entity(slack_approval_message::Entity))
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(slack_approval_message::Entity)
                    .to_owned(),
            )
            .await?;
        for column in ["slack_enabled"]
            .into_iter()
            .chain(SECRET_COLUMNS)
            .chain(OPTIONAL_COLUMNS)
        {
            manager
                .alter_table(
                    Table::alter()
                        .table(parameters::Entity)
                        .drop_column(Alias::new(column))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
