use sea_orm_migration::prelude::*;

use crate::m00010_parameters::parameters;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00042_password_policy"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("password_policy_min_length"))
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .add_column(
                        ColumnDef::new(Alias::new("password_policy_require_uppercase"))
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .add_column(
                        ColumnDef::new(Alias::new("password_policy_require_lowercase"))
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .add_column(
                        ColumnDef::new(Alias::new("password_policy_require_digits"))
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .add_column(
                        ColumnDef::new(Alias::new("password_policy_require_special"))
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .drop_column(Alias::new("password_policy_min_length"))
                    .drop_column(Alias::new("password_policy_require_uppercase"))
                    .drop_column(Alias::new("password_policy_require_lowercase"))
                    .drop_column(Alias::new("password_policy_require_digits"))
                    .drop_column(Alias::new("password_policy_require_special"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
