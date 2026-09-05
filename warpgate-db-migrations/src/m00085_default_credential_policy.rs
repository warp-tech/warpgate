use sea_orm_migration::prelude::*;

use crate::helpers::string_default_value;
use crate::m00010_parameters::parameters;

#[derive(DeriveMigrationName)]
pub struct Migration;

// UserRequireCredentialsPolicy::default()
const DEFAULT_POLICY: &str = "{}";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("default_credential_policy"))
                            .text()
                            .not_null()
                            .default(string_default_value(backend, DEFAULT_POLICY)),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .drop_column(Alias::new("default_credential_policy"))
                    .to_owned(),
            )
            .await
    }
}
