use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .name("idx_target_roles_target_role")
                    .table(Alias::new("target_roles"))
                    .col(Alias::new("target_id"))
                    .col(Alias::new("role_id"))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_user_roles_user_role")
                    .table(Alias::new("user_roles"))
                    .col(Alias::new("user_id"))
                    .col(Alias::new("role_id"))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_targets_name")
                    .table(Alias::new("targets"))
                    .col(Alias::new("name"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_targets_name")
                    .table(Alias::new("targets"))
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_user_roles_user_role")
                    .table(Alias::new("user_roles"))
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_target_roles_target_role")
                    .table(Alias::new("target_roles"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
