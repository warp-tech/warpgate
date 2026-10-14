use sea_orm_migration::prelude::*;

const COLUMNS: [&str; 3] = ["sso_provider", "sso_subject", "sso_sid"];
const INDEXES: [(&str, &str); 2] = [
    ("idx_http_sessions_sso_subject", "sso_subject"),
    ("idx_http_sessions_sso_sid", "sso_sid"),
];

/// Mirrors the SSO identity a browser session logged in with out of its `data`
/// JSON, so an OIDC back-channel logout can find the sessions it names. Rows
/// are re-mirrored on their next save; no backfill.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for column in COLUMNS {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("http_sessions"))
                        .add_column(ColumnDef::new(Alias::new(column)).string_len(255).null())
                        .to_owned(),
                )
                .await?;
        }
        for (name, column) in INDEXES {
            manager
                .create_index(
                    Index::create()
                        .name(name)
                        .table(Alias::new("http_sessions"))
                        .col(Alias::new("sso_provider"))
                        .col(Alias::new(column))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (name, _) in INDEXES {
            manager
                .drop_index(
                    Index::drop()
                        .name(name)
                        .table(Alias::new("http_sessions"))
                        .to_owned(),
                )
                .await?;
        }
        for column in COLUMNS {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("http_sessions"))
                        .drop_column(Alias::new(column))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
