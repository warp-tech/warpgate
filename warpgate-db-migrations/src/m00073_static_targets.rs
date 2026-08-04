use sea_orm_migration::prelude::*;

/// Marks rows that are owned by a statically-defined targets file (see
/// `warpgate-core::static_targets`) rather than created through the admin
/// API/UI, so the reconciler knows what it may safely update or delete on the
/// next sync, and the admin API can refuse edits that would just get
/// overwritten.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in ["targets", "target_groups", "roles"] {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new(table))
                        .add_column(
                            ColumnDef::new(Alias::new("static_managed"))
                                .boolean()
                                .not_null()
                                .default(false),
                        )
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in ["targets", "target_groups", "roles"] {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new(table))
                        .drop_column(Alias::new("static_managed"))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
