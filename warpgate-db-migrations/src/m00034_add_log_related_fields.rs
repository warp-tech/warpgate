use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("log"))
                    .add_column_if_not_exists(
                        ColumnDef::new(Alias::new("related_users")).string().null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(Alias::new("log"))
                    .name("log_related_users")
                    .col(Alias::new("related_users"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("log"))
                    .add_column_if_not_exists(
                        ColumnDef::new(Alias::new("related_access_roles"))
                            .string()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(Alias::new("log"))
                    .name("log_related_access_roles")
                    .col(Alias::new("related_access_roles"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("log"))
                    .add_column_if_not_exists(
                        ColumnDef::new(Alias::new("related_admin_roles"))
                            .string()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(Alias::new("log"))
                    .name("log_related_admin_roles")
                    .col(Alias::new("related_admin_roles"))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("log"))
                    .drop_column(Alias::new("related_access_roles"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("log"))
                    .drop_column(Alias::new("related_admin_roles"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("log"))
                    .drop_column(Alias::new("related_users"))
                    .to_owned(),
            )
            .await
    }
}
