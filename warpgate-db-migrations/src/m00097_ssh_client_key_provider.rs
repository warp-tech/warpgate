use sea_orm_migration::prelude::*;

use crate::m00079_unique_target_and_group_names::{add_unique_name_index, drop_unique_name_index};
use crate::m00096_resource_provider::{add_provider_column, drop_provider_column};

/// Client keys become provider-ownable, and resource files refer to them by
/// label, so labels must be unique
#[derive(DeriveMigrationName)]
pub struct Migration;

const TABLE: &str = "ssh_client_keys";
const INDEX: &str = "ssh_client_keys_label_unique";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        add_provider_column(manager, TABLE).await?;
        add_unique_name_index(manager, TABLE, "label", INDEX).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        drop_unique_name_index(manager, TABLE, INDEX).await?;
        drop_provider_column(manager, TABLE).await
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::{ConnectionTrait, Database, Statement};
    use sea_orm_migration::MigratorTrait;
    use sea_orm_migration::prelude::{Alias, Query};
    use uuid::Uuid;
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};

    use crate::Migrator;

    #[tokio::test]
    async fn duplicate_labels_are_renamed_and_then_rejected() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        crate::migrate_up_to(&db, "m00097_ssh_client_key_provider").await;

        let backend = db.get_database_backend();
        let insert = |label: &str| {
            backend.build(
                Query::insert()
                    .into_table(Alias::new("ssh_client_keys"))
                    .columns(
                        ["id", "label", "secret_key", "public_key", "is_default"].map(Alias::new),
                    )
                    .values_panic([
                        Uuid::new_v4().into(),
                        label.into(),
                        "".into(),
                        Uuid::new_v4().to_string().into(),
                        false.into(),
                    ]),
            )
        };
        for label in ["deploy", "deploy", "ci"] {
            db.execute_raw(insert(label)).await.unwrap();
        }

        Migrator::up(&db, None).await.unwrap();

        let rows = db
            .query_all_raw(Statement::from_string(
                backend,
                "SELECT label, provider FROM ssh_client_keys ORDER BY label",
            ))
            .await
            .unwrap();
        let labels: Vec<String> = rows
            .iter()
            .map(|row| row.try_get("", "label").unwrap())
            .collect();
        assert_eq!(labels, ["ci", "deploy", "deploy (2)"]);
        for row in &rows {
            let provider: Option<Uuid> = row.try_get("", "provider").unwrap();
            assert_eq!(provider, None);
        }

        db.execute_raw(insert("ci"))
            .await
            .expect_err("the unique index must reject a duplicate label");
    }
}
