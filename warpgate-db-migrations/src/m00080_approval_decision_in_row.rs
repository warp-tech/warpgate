use sea_orm_migration::prelude::*;

use crate::m00078_jit_session_approval::session_approval_request;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Carries the decision itself, so an approval request is resolved by writing to
/// its row from any node rather than by reaching the owner directly. The owning
/// node reads the decision back off the row.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Existing rows are by definition still waiting: they only survive an
        // upgrade if nothing had resolved them.
        manager
            .alter_table(
                Table::alter()
                    .table(session_approval_request::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("status"))
                            .string_len(16)
                            .not_null()
                            .default("pending"),
                    )
                    .to_owned(),
            )
            .await?;

        // Only meaningful once approved: how widely the grant is remembered.
        manager
            .alter_table(
                Table::alter()
                    .table(session_approval_request::Entity)
                    .add_column(ColumnDef::new(Alias::new("scope")).string_len(16))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(session_approval_request::Entity)
                    .add_column(ColumnDef::new(Alias::new("resolved_by_username")).string())
                    .to_owned(),
            )
            .await?;

        // Null for a resolver that isn't a user, such as the admin API token.
        manager
            .alter_table(
                Table::alter()
                    .table(session_approval_request::Entity)
                    .add_column(ColumnDef::new(Alias::new("resolved_by_user_id")).uuid())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for column in [
            "status",
            "scope",
            "resolved_by_username",
            "resolved_by_user_id",
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(session_approval_request::Entity)
                        .drop_column(Alias::new(column))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
