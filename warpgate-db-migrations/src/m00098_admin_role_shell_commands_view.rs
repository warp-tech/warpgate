use sea_orm_migration::prelude::*;

/// Admin roles gain a separate permission for the shell command log, which
/// until now rode on `sessions_view`.
///
/// `DEFAULT false` means every existing row reads back `false` (never NULL) and
/// no role gains access it did not already have — except the built-in admin
/// role, which is switched on explicitly below so an upgraded install keeps
/// seeing the page it just started gating.
#[derive(DeriveMigrationName)]
pub struct Migration;

const ADMIN_ROLES: &str = "admin_roles";
const SHELL_COMMANDS_VIEW: &str = "shell_commands_view";
const BUILTIN_ADMIN_ROLE_NAME: &str = "warpgate:admin";

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

        // Same step (and literal name) as m00044 did for its own new
        // permission: the built-in role is full-permission by definition.
        let conn = manager.get_connection();
        let bool_true = match manager.get_database_backend() {
            sea_orm::DatabaseBackend::Postgres => "TRUE",
            _ => "1",
        };
        conn.execute_unprepared(&format!(
            "UPDATE \"{ADMIN_ROLES}\" SET \"{SHELL_COMMANDS_VIEW}\" = {bool_true} WHERE name = '{BUILTIN_ADMIN_ROLE_NAME}'",
        ))
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
