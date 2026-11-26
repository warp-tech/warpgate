use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// The node writing a recording. It can differ from the session's node: each
/// node serving a Kubernetes session writes its own recording. Existing rows
/// stay NULL. Their session's node wrote them
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("recordings"))
                    .add_column(ColumnDef::new(Alias::new("node_id")).uuid().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("recordings"))
                    .drop_column(Alias::new("node_id"))
                    .to_owned(),
            )
            .await
    }
}
