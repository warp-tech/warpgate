use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

/// timestamp_with_time_zone() was originally missing on user_roles role assignment columns
pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00041_fix_user_role_assignment_dates"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let connection = manager.get_connection();
        if connection.get_database_backend() != DbBackend::Sqlite {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("user_roles"))
                        .modify_column(
                            ColumnDef::new(Alias::new("granted_at"))
                                .date_time()
                                .timestamp_with_time_zone()
                                .null(),
                        )
                        .to_owned(),
                )
                .await?;

            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("user_roles"))
                        .modify_column(
                            ColumnDef::new(Alias::new("expires_at"))
                                .date_time()
                                .timestamp_with_time_zone()
                                .null(),
                        )
                        .to_owned(),
                )
                .await?;

            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("user_roles"))
                        .modify_column(
                            ColumnDef::new(Alias::new("revoked_at"))
                                .date_time()
                                .timestamp_with_time_zone()
                                .null(),
                        )
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let connection = manager.get_connection();
        if connection.get_database_backend() != DbBackend::Sqlite {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("user_roles"))
                        .modify_column(ColumnDef::new(Alias::new("granted_at")).date_time().null())
                        .to_owned(),
                )
                .await?;

            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("user_roles"))
                        .modify_column(ColumnDef::new(Alias::new("expires_at")).date_time().null())
                        .to_owned(),
                )
                .await?;

            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("user_roles"))
                        .modify_column(ColumnDef::new(Alias::new("revoked_at")).date_time().null())
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }
}
