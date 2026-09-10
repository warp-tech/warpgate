use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // SPKI SHA-256 pin of the node's per-boot cluster TLS certificate;
        // peers verify the proxy connection's server key against it. Null for
        // rows written by nodes from before cluster TLS.
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("nodes"))
                    .add_column(ColumnDef::new(Alias::new("tls_spki_sha256")).text().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("nodes"))
                    .drop_column(Alias::new("tls_spki_sha256"))
                    .to_owned(),
            )
            .await
    }
}
