use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("parameters"))
                    .add_column(
                        ColumnDef::new(Alias::new("encryption_key_fp"))
                            .text()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("parameters"))
                    .add_column(ColumnDef::new(Alias::new("retiring_key_fp")).text().null())
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("nodes"))
                    .add_column(
                        ColumnDef::new(Alias::new("encryption_key_fingerprint"))
                            .text()
                            .null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("parameters"))
                    .drop_column(Alias::new("encryption_key_fp"))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("parameters"))
                    .drop_column(Alias::new("retiring_key_fp"))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("nodes"))
                    .drop_column(Alias::new("encryption_key_fingerprint"))
                    .to_owned(),
            )
            .await
    }
}
