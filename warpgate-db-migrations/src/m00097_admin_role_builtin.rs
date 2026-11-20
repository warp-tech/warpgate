use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

const TABLE: &str = "admin_roles";
const COLUMN: &str = "builtin";
const BUILTIN_ADMIN_ROLE_NAME: &str = "warpgate:admin";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new(TABLE))
                    .add_column(
                        ColumnDef::new(Alias::new(COLUMN))
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;

        // Names are unique by now, so this marks exactly the built-in role.
        let db = manager.get_connection();
        db.execute(
            db.get_database_backend().build(
                Query::update()
                    .table(Alias::new(TABLE))
                    .value(Alias::new(COLUMN), true)
                    .and_where(Expr::col(Alias::new("name")).eq(BUILTIN_ADMIN_ROLE_NAME)),
            ),
        )
        .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new(TABLE))
                    .drop_column(Alias::new(COLUMN))
                    .to_owned(),
            )
            .await
    }
}
