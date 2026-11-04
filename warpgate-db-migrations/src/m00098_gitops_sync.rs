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

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::{ActiveModelTrait, Database, EntityTrait, IntoActiveModel, Set};
    use sea_orm_migration::MigratorTrait;
    use warpgate_common::MaybeSecretRef;
    use warpgate_db_entities::Parameters::{
        self, ConfigMigrationValues, GitopsGitSource, GitopsSource, set_config_migration_values,
    };
    use warpgate_db_entities::ProviderSync;

    use crate::Migrator;

    #[tokio::test]
    async fn adds_the_gitops_parameters_and_the_sync_history() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        crate::migrate_up_to(&db, "m00098_gitops_sync").await;
        Migrator::up(&db, None).await.unwrap();

        let parameters = Parameters::Entity::get(&db).await.unwrap();
        assert_eq!(parameters.gitops_source, None);
        assert!(!parameters.gitops_prune);

        let source = GitopsSource::Git(GitopsGitSource {
            url: "https://git.example.com/infra.git".into(),
            reference: "main".into(),
            username: Some("ci".into()),
            password: "secret://vault/kv/git#token"
                .parse::<MaybeSecretRef>()
                .unwrap(),
            path: Some("warpgate".into()),
        });
        let mut model = parameters.into_active_model();
        model.gitops_source = Set(Some(source.clone()));
        model.update(&db).await.unwrap();
        assert_eq!(
            Parameters::Entity::get(&db).await.unwrap().gitops_source,
            Some(source)
        );
        assert!(
            ProviderSync::Entity::find()
                .all(&db)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
