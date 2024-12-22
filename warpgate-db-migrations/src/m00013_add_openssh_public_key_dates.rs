use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00013_add_openssh_public_key_dates"
    }
}

use crate::m00009_credential_models::public_key_credential;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add 'date_added' column
        manager
            .alter_table(
                Table::alter()
                    .table(public_key_credential::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("date_added"))
                            .date_time()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Add 'last_used' column
        manager
            .alter_table(
                Table::alter()
                    .table(public_key_credential::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("last_used"))
                            .date_time()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop 'last_used' column
        manager
            .alter_table(
                Table::alter()
                    .table(public_key_credential::Entity)
                    .drop_column(Alias::new("last_used"))
                    .to_owned(),
            )
            .await?;

        // Drop 'date_added' column
        manager
            .alter_table(
                Table::alter()
                    .table(public_key_credential::Entity)
                    .drop_column(Alias::new("date_added"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
