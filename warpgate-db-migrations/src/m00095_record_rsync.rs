use sea_orm_migration::prelude::*;

use crate::m00010_parameters::parameters;

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
                        ColumnDef::new(Alias::new("record_rsync"))
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .drop_column(Alias::new("record_rsync"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::{ConnectionTrait, Database, Statement};

    use super::*;

    #[tokio::test]
    async fn upgrades_existing_settings_without_disabling_recordings() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_unprepared(
            "CREATE TABLE parameters (id INTEGER PRIMARY KEY, record_scp BOOLEAN NOT NULL)",
        )
        .await
        .unwrap();
        db.execute_unprepared("INSERT INTO parameters VALUES (1, FALSE)")
            .await
            .unwrap();
        let manager = SchemaManager::new(&db);

        Migration.up(&manager).await.unwrap();
        let row = db
            .query_one(Statement::from_string(
                db.get_database_backend(),
                "SELECT record_scp, record_rsync FROM parameters",
            ))
            .await
            .unwrap()
            .unwrap();
        assert!(!row.try_get::<bool>("", "record_scp").unwrap());
        assert!(row.try_get::<bool>("", "record_rsync").unwrap());

        Migration.down(&manager).await.unwrap();
        assert!(
            !manager
                .has_column("parameters", "record_rsync")
                .await
                .unwrap()
        );
        Migration.up(&manager).await.unwrap();
        assert!(
            manager
                .has_column("parameters", "record_rsync")
                .await
                .unwrap()
        );
    }
}
