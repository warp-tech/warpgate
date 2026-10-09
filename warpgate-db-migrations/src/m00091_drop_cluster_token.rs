use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Cluster peers authenticate with their pinned TLS identity; the shared
        // bearer secret has no remaining reader.
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("parameters"))
                    .drop_column(Alias::new("cluster_token"))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("parameters"))
                    .add_column(ColumnDef::new(Alias::new("cluster_token")).text().null())
                    .to_owned(),
            )
            .await
    }
}
