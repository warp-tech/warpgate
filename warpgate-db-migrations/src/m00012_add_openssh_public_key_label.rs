use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00012_add_openssh_public_key_label"
    }
}

use crate::m00009_credential_models::public_key_credential;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(public_key_credential::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("label"))
                            .string()
                            .not_null()
                    ).to_owned()
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(public_key_credential::Entity)
                    .drop_column(Alias::new("label"))
                    .to_owned(),
            )
            .await
    }

}
