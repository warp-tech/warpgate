use sea_orm_migration::prelude::*;

use crate::m00008_users::user;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(user::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("show_session_menu"))
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(user::Entity)
                    .drop_column(Alias::new("show_session_menu"))
                    .to_owned(),
            )
            .await
    }
}
