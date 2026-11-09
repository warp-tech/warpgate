use sea_orm_migration::prelude::*;

use crate::m00010_parameters::parameters;

const COLUMN: &str = "gitops_sync_on_startup";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new(COLUMN))
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .drop_column(Alias::new(COLUMN))
                    .to_owned(),
            )
            .await
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::Database;
    use sea_orm_migration::MigratorTrait;
    use warpgate_db_entities::Parameters::{
        self, ConfigMigrationValues, set_config_migration_values,
    };

    use crate::Migrator;

    #[tokio::test]
    async fn existing_installations_keep_syncing_on_startup() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        crate::migrate_up_to(&db, "m00098_gitops_sync").await;
        Migrator::up(&db, None).await.unwrap();

        assert!(
            Parameters::Entity::get(&db)
                .await
                .unwrap()
                .gitops_sync_on_startup
        );
    }
}
