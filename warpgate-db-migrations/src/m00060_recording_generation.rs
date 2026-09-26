use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Recordings gained a storage generation: gen 1 = a single file (legacy), gen 2 =
/// a folder holding `data.ndjson` (+ a desktop seek `index.json`). Existing rows are
/// gen 1 via the column default; new recordings insert gen 2 explicitly.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("recordings"))
                    .add_column(
                        ColumnDef::new(Alias::new("generation"))
                            .integer()
                            .not_null()
                            .default(1),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("recordings"))
                    .drop_column(Alias::new("generation"))
                    .to_owned(),
            )
            .await
    }
}
