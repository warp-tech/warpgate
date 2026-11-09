use sea_orm::Schema;
use sea_orm_migration::prelude::*;

use crate::m00010_parameters::parameters;

pub mod provider_sync {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "provider_syncs")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub provider: Uuid,
        #[sea_orm(column_type = "String(StringLen::N(16))")]
        pub triggered_by: String,
        #[sea_orm(column_type = "String(StringLen::N(16))")]
        pub status: String,
        pub started_at: OffsetDateTime,
        pub checked_at: OffsetDateTime,
        #[sea_orm(column_type = "Text")]
        pub source: String,
        #[sea_orm(column_type = "Text", nullable)]
        pub revision: Option<String>,
        #[sea_orm(column_type = "Json", nullable)]
        pub plan: Option<serde_json::Value>,
        #[sea_orm(column_type = "Text", nullable)]
        pub error: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

const INDEX: &str = "provider_syncs__provider__started_at";

fn parameter_columns() -> [ColumnDef; 4] {
    [
        ColumnDef::new(Alias::new("gitops_source"))
            .json()
            .null()
            .to_owned(),
        ColumnDef::new(Alias::new("gitops_sync_interval_seconds"))
            .big_integer()
            .null()
            .to_owned(),
        ColumnDef::new(Alias::new("gitops_webhook_secret"))
            .text()
            .null()
            .to_owned(),
        ColumnDef::new(Alias::new("gitops_prune"))
            .boolean()
            .not_null()
            .default(false)
            .to_owned(),
    ]
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // SQLite takes one column per ALTER TABLE
        for mut column in parameter_columns() {
            manager
                .alter_table(
                    Table::alter()
                        .table(parameters::Entity)
                        .add_column(&mut column)
                        .to_owned(),
                )
                .await?;
        }

        let schema = Schema::new(manager.get_database_backend());
        manager
            .create_table(schema.create_table_from_entity(provider_sync::Entity))
            .await?;
        manager
            .create_index(
                Index::create()
                    .name(INDEX)
                    .table(provider_sync::Entity)
                    .col(provider_sync::Column::Provider)
                    .col(provider_sync::Column::StartedAt)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(provider_sync::Entity).to_owned())
            .await?;
        for column in parameter_columns() {
            manager
                .alter_table(
                    Table::alter()
                        .table(parameters::Entity)
                        .drop_column(Alias::new(column.get_column_name()))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
