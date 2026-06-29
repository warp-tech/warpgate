use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

use crate::m00010_parameters::parameters;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("password_login_mode"))
                            .string()
                            .not_null()
                            .default("Enabled"),
                    )
                    .to_owned(),
            )
            .await?;

        // Carry over the previous boolean: a minimized password form maps to
        // the new "Minimized" mode, everything else stays "Enabled".
        let db = manager.get_connection();
        let backend = db.get_database_backend();
        let stmt = Query::update()
            .table(parameters::Entity)
            .value(Alias::new("password_login_mode"), "Minimized")
            .and_where(Expr::col(Alias::new("minimize_password_login")).eq(true))
            .to_owned();
        db.execute(backend.build(&stmt)).await?;

        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .drop_column(Alias::new("minimize_password_login"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("minimize_password_login"))
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;

        let db = manager.get_connection();
        let backend = db.get_database_backend();
        let stmt = Query::update()
            .table(parameters::Entity)
            .value(Alias::new("minimize_password_login"), true)
            .and_where(Expr::col(Alias::new("password_login_mode")).eq("Minimized"))
            .to_owned();
        db.execute(backend.build(&stmt)).await?;

        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .drop_column(Alias::new("password_login_mode"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
