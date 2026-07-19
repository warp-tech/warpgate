use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

use crate::m00032_admin_roles::admin_role;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(admin_role::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("approve_sessions"))
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;

        // Before this permission existed, holding administrator approval
        // authority was implied by being able to see sessions at all. Granting
        // it to every such role keeps existing deployments working; the column
        // defaults to off for roles created afterwards.
        let bool_true = match manager.get_database_backend() {
            sea_orm::DatabaseBackend::Postgres => "TRUE",
            _ => "1",
        };
        manager
            .get_connection()
            .execute_unprepared(&format!(
                "UPDATE admin_roles SET approve_sessions = {bool_true} WHERE sessions_view = {bool_true}"
            ))
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(admin_role::Entity)
                    .drop_column(Alias::new("approve_sessions"))
                    .to_owned(),
            )
            .await
    }
}
