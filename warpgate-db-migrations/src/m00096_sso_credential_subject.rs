use sea_orm_migration::prelude::*;

/// Store the IdP's subject (`sub`) on an SSO credential, so a credential can be
/// matched by the immutable subject instead of only the e-mail address. Nullable:
/// existing credentials keep matching by e-mail until a subject is set.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(Iden)]
enum CredentialsSso {
    Table,
    Subject,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(CredentialsSso::Table)
                    .add_column(ColumnDef::new(CredentialsSso::Subject).string().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(CredentialsSso::Table)
                    .drop_column(CredentialsSso::Subject)
                    .to_owned(),
            )
            .await
    }
}
