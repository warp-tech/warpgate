use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("user_roles"))
                    .add_column(ColumnDef::new(Alias::new("granted_at")).timestamp().null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("user_roles"))
                    .add_column(ColumnDef::new(Alias::new("expires_at")).timestamp().null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("user_roles"))
                    .add_column(ColumnDef::new(Alias::new("revoked_at")).timestamp().null())
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
                    .drop_column(Alias::new("granted_at"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("user_roles"))
                    .drop_column(Alias::new("expires_at"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("user_roles"))
                    .drop_column(Alias::new("revoked_at"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
