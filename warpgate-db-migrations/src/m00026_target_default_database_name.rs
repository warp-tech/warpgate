use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00026_target_default_database_name"
    }
}

use crate::m00007_targets_and_roles::target;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let connection = manager.get_connection();
        let backend = connection.get_database_backend();
        
        // Check if column already exists by trying to query it
        let column_exists = match backend {
            DbBackend::Postgres => {
                let stmt = sea_orm::Statement::from_string(
                    backend,
                    "SELECT default_database_name FROM targets LIMIT 0",
                );
                connection.execute(stmt).await.is_ok()
            }
            DbBackend::Sqlite => {
                let stmt = sea_orm::Statement::from_string(
                    backend,
                    "SELECT default_database_name FROM targets LIMIT 0",
                );
                connection.execute(stmt).await.is_ok()
            }
            DbBackend::MySql => {
                let stmt = sea_orm::Statement::from_string(
                    backend,
                    "SELECT default_database_name FROM targets LIMIT 0",
                );
                connection.execute(stmt).await.is_ok()
            }
        };

        // Only add column if it doesn't exist
        if !column_exists {
            manager
                .alter_table(
                    Table::alter()
                        .table(target::Entity)
                        .add_column(
                            ColumnDef::new(Alias::new("default_database_name"))
                                .string()
                                .null(),
                        )
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Try to drop the column, ignore error if it doesn't exist
        let _ = manager
            .alter_table(
                Table::alter()
                    .table(target::Entity)
                    .drop_column(Alias::new("default_database_name"))
                    .to_owned(),
            )
            .await;

        Ok(())
    }
}

