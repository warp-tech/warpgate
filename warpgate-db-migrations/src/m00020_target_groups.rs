use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00020_target_groups"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create target_groups table
        manager
            .create_table(
                Table::create()
                    .table(TargetGroups::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(TargetGroups::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(TargetGroups::Name)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TargetGroups::Description)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TargetGroups::Color)
                            .string()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Add group_id column to targets table
        manager
            .alter_table(
                Table::alter()
                    .table(Targets::Table)
                    .add_column(
                        ColumnDef::new(Targets::GroupId)
                            .uuid()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Note: SQLite doesn't support adding foreign key constraints to existing tables
        // The foreign key relationship will be enforced at the application level

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Remove group_id column from targets table
        manager
            .alter_table(
                Table::alter()
                    .table(Targets::Table)
                    .drop_column(Targets::GroupId)
                    .to_owned(),
            )
            .await?;

        // Drop target_groups table
        manager
            .drop_table(
                Table::drop()
                    .table(TargetGroups::Table)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum TargetGroups {
    Table,
    Id,
    Name,
    Description,
    Color,
}

#[derive(DeriveIden)]
enum Targets {
    Table,
    GroupId,
}
