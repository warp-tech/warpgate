use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Shared secret authenticating cross-node recording proxying. Null until
        // the first node boots and generates one (see `Services::new`).
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("parameters"))
                    .add_column(ColumnDef::new(Alias::new("cluster_token")).text().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("parameters"))
                    .drop_column(Alias::new("cluster_token"))
                    .to_owned(),
            )
            .await
    }
}
