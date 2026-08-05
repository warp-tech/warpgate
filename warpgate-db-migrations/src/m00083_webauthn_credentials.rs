use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00083_webauthn_credentials"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(WebauthnCredential::Table)
                    .col(
                        ColumnDef::new(WebauthnCredential::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(WebauthnCredential::UserId).uuid().not_null())
                    .col(
                        ColumnDef::new(WebauthnCredential::Label)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WebauthnCredential::CredentialId)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WebauthnCredential::CredentialJson)
                            .text()
                            .not_null(),
                    )
                    .col(ColumnDef::new(WebauthnCredential::DateAdded).timestamp_with_time_zone())
                    .col(ColumnDef::new(WebauthnCredential::LastUsed).timestamp_with_time_zone())
                    .foreign_key(
                        ForeignKey::create()
                            .from(WebauthnCredential::Table, WebauthnCredential::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_credentials_webauthn_user_id")
                    .table(WebauthnCredential::Table)
                    .col(WebauthnCredential::UserId)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(WebauthnCredential::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum WebauthnCredential {
    #[iden = "credentials_webauthn"]
    Table,
    Id,
    UserId,
    Label,
    CredentialId,
    CredentialJson,
    DateAdded,
    LastUsed,
}

#[derive(Iden)]
enum Users {
    Table,
    Id,
}
