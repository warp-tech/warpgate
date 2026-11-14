use sea_orm_migration::prelude::*;

/// Tracks the source of role assignments. Existing rows keep NULL so legacy
/// grants remain revocable by SSO sync.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("user_roles"))
                    .add_column(ColumnDef::new(Alias::new("source")).string_len(16).null())
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("user_roles"))
                    .drop_column(Alias::new("source"))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
