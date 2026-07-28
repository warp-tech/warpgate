use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;
use uuid::Uuid;

/// Backfills legacy `sessions.node_id` NULLs (pre-clustering, or once an owner
/// was gone) with the nil UUID and makes the column non-nullable, so the entity
/// can drop the `Option`. The nil UUID is the in-code sentinel for "no owning
/// node" (see `cluster_proxy::node_owner`).
pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00071_session_node_id_not_null"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .exec_stmt(
                Query::update()
                    .table(Alias::new("sessions"))
                    .value(Alias::new("node_id"), Uuid::nil())
                    .and_where(Expr::col(Alias::new("node_id")).is_null())
                    .to_owned(),
            )
            .await?;

        // SQLite is dynamically typed and cannot alter a column's nullability in
        // place; the backfill above plus the app always writing a node_id keeps
        // the column NULL-free there.
        if manager.get_database_backend() != DbBackend::Sqlite {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("sessions"))
                        .modify_column(ColumnDef::new(Alias::new("node_id")).uuid().not_null())
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() != DbBackend::Sqlite {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("sessions"))
                        .modify_column(ColumnDef::new(Alias::new("node_id")).uuid().null())
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
