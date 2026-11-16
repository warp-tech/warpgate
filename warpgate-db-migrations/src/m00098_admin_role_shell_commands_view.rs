use sea_orm_migration::prelude::*;

/// Admin roles gain a separate permission for the shell command log, which
/// until now rode on `sessions_view`.
///
/// `DEFAULT false` means every existing row reads back `false` (never NULL).
/// Roles that could already see the log are switched on explicitly below, so an
/// upgraded install keeps seeing the page it just started gating.
#[derive(DeriveMigrationName)]
pub struct Migration;

const ADMIN_ROLES: &str = "admin_roles";
const SHELL_COMMANDS_VIEW: &str = "shell_commands_view";

/// The backfill runs as raw SQL on every backend, so the identifiers stay
/// unquoted: sqlite and postgres also accept `"..."`, but mysql/mariadb only
/// treat it as an identifier with `ANSI_QUOTES` and otherwise read a string
/// literal (`ER_PARSE_ERROR`).
fn backfill_statement(backend: sea_orm::DatabaseBackend) -> String {
    let bool_true = match backend {
        sea_orm::DatabaseBackend::Postgres => "TRUE",
        _ => "1",
    };
    format!(
        "UPDATE {ADMIN_ROLES} SET {SHELL_COMMANDS_VIEW} = {bool_true} WHERE sessions_view = {bool_true}"
    )
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new(ADMIN_ROLES))
                    .add_column(
                        ColumnDef::new(Alias::new(SHELL_COMMANDS_VIEW))
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;

        // Before this permission existed the command log was gated on
        // `sessions_view`, so every role that could see it must keep seeing it.
        // Behaviour-based like m00086's `approve_sessions` backfill, which also
        // makes it rename-proof and idempotent.
        manager
            .get_connection()
            .execute_unprepared(&backfill_statement(manager.get_database_backend()))
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // A real drop on every backend, following m00092's column removals.
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new(ADMIN_ROLES))
                    .drop_column(Alias::new(SHELL_COMMANDS_VIEW))
                    .to_owned(),
            )
            .await
    }
}
