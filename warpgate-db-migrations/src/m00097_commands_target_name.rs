use sea_orm_migration::prelude::*;

/// Detected commands gain the name of the target they ran against.
///
/// Nullable: a command detected before any target is resolved (the target
/// selection menu) legitimately has none, and so does every row written by a
/// binary that predates this column.
#[derive(DeriveMigrationName)]
pub struct Migration;

const COMMANDS: &str = "commands";
const TARGET_NAME: &str = "target_name";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Adding a nullable column in place is supported by every backend
        // (SQLite included), so no table rebuild is needed here.
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new(COMMANDS))
                    .add_column(ColumnDef::new(Alias::new(TARGET_NAME)).text().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // A real drop on every backend, like m00092's column removals:
        // sea-orm emits `ALTER TABLE ... DROP COLUMN` for SQLite too, which the
        // bundled SQLite (>= 3.35) supports.
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new(COMMANDS))
                    .drop_column(Alias::new(TARGET_NAME))
                    .to_owned(),
            )
            .await
    }
}
