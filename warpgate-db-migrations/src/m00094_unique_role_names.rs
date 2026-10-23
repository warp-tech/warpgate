use sea_orm_migration::prelude::*;

use crate::m00079_unique_target_and_group_names::{add_unique_name_index, drop_unique_name_index};

#[derive(DeriveMigrationName)]
pub struct Migration;

const TABLE: &str = "roles";
const INDEX: &str = "roles_name_unique";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        add_unique_name_index(manager, TABLE, INDEX).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        drop_unique_name_index(manager, TABLE, INDEX).await
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
    async fn duplicate_role_names_are_renamed_and_then_rejected() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        let before = u32::try_from(
            Migrator::migrations()
                .iter()
                .position(|m| m.name() == "m00094_unique_role_names")
                .unwrap(),
        )
        .unwrap();
        Migrator::up(&db, Some(before)).await.unwrap();

        let backend = db.get_database_backend();
        let insert = |name: &str| {
            backend.build(
                Query::insert()
                    .into_table(Alias::new("roles"))
                    .columns(["id", "name", "description", "is_default"].map(Alias::new))
                    .values_panic([Uuid::new_v4().into(), name.into(), "".into(), false.into()]),
            )
        };
        for name in ["dba", "dba", "ops"] {
            db.execute(insert(name)).await.unwrap();
        }

        Migrator::up(&db, None).await.unwrap();

        let names: Vec<String> = db
            .query_all(Statement::from_string(
                backend,
                "SELECT name FROM roles ORDER BY name",
            ))
            .await
            .unwrap()
            .iter()
            .map(|row| row.try_get("", "name").unwrap())
            .collect();
        assert_eq!(names, ["dba", "dba (2)", "ops"]);

        db.execute(insert("ops"))
            .await
            .expect_err("the unique index must reject a duplicate role name");
    }
}
