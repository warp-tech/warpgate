use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;
use warpgate_common::auth::CredentialDigestSalt;

use crate::helpers::string_default_value;
use crate::m00010_parameters::parameters;

#[derive(DeriveMigrationName)]
pub struct Migration;

const COLUMN: &str = "credential_digest_salt";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = db.get_database_backend();

        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new(COLUMN))
                            .text()
                            .not_null()
                            .default(string_default_value(backend, "")),
                    )
                    .to_owned(),
            )
            .await?;

        // Existing installations get their salt here; the blank guard makes the
        // stamp idempotent and leaves a salt already in place alone — rewriting
        // one would orphan every digest stored under it.
        let stmt = Query::update()
            .table(parameters::Entity)
            .value(
                Alias::new(COLUMN),
                CredentialDigestSalt::random().expose_secret(),
            )
            .and_where(Expr::col(Alias::new(COLUMN)).eq(""))
            .to_owned();
        db.execute(backend.build(&stmt)).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .drop_column(Alias::new(COLUMN))
                    .to_owned(),
            )
            .await
    }
}
