use sea_orm_migration::prelude::*;

use crate::m00010_parameters::parameters;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00047_login_protection_params"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("login_protection_enabled"))
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .add_column(
                        ColumnDef::new(Alias::new("login_protection_retention_days"))
                            .integer()
                            .not_null()
                            .default(30),
                    )
                    .add_column(
                        ColumnDef::new(Alias::new("lp_ip_max_attempts"))
                            .integer()
                            .not_null()
                            .default(5),
                    )
                    .add_column(
                        ColumnDef::new(Alias::new("lp_ip_time_window_minutes"))
                            .integer()
                            .not_null()
                            .default(15),
                    )
                    .add_column(
                        ColumnDef::new(Alias::new("lp_ip_base_block_duration_minutes"))
                            .integer()
                            .not_null()
                            .default(30),
                    )
                    .add_column(
                        ColumnDef::new(Alias::new("lp_ip_block_duration_multiplier"))
                            .double()
                            .not_null()
                            .default(2.0),
                    )
                    .add_column(
                        ColumnDef::new(Alias::new("lp_ip_max_block_duration_hours"))
                            .integer()
                            .not_null()
                            .default(24),
                    )
                    .add_column(
                        ColumnDef::new(Alias::new("lp_ip_cooldown_reset_hours"))
                            .integer()
                            .not_null()
                            .default(24),
                    )
                    .add_column(
                        ColumnDef::new(Alias::new("lp_ip_blocked_message"))
                            .text()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(Alias::new("lp_user_max_attempts"))
                            .integer()
                            .not_null()
                            .default(10),
                    )
                    .add_column(
                        ColumnDef::new(Alias::new("lp_user_time_window_minutes"))
                            .integer()
                            .not_null()
                            .default(60),
                    )
                    .add_column(
                        ColumnDef::new(Alias::new("lp_user_auto_unlock"))
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .add_column(
                        ColumnDef::new(Alias::new("lp_user_lockout_duration_minutes"))
                            .integer()
                            .not_null()
                            .default(60),
                    )
                    .add_column(
                        ColumnDef::new(Alias::new("lp_user_locked_message"))
                            .text()
                            .null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .drop_column(Alias::new("login_protection_enabled"))
                    .drop_column(Alias::new("login_protection_retention_days"))
                    .drop_column(Alias::new("lp_ip_max_attempts"))
                    .drop_column(Alias::new("lp_ip_time_window_minutes"))
                    .drop_column(Alias::new("lp_ip_base_block_duration_minutes"))
                    .drop_column(Alias::new("lp_ip_block_duration_multiplier"))
                    .drop_column(Alias::new("lp_ip_max_block_duration_hours"))
                    .drop_column(Alias::new("lp_ip_cooldown_reset_hours"))
                    .drop_column(Alias::new("lp_ip_blocked_message"))
                    .drop_column(Alias::new("lp_user_max_attempts"))
                    .drop_column(Alias::new("lp_user_time_window_minutes"))
                    .drop_column(Alias::new("lp_user_auto_unlock"))
                    .drop_column(Alias::new("lp_user_lockout_duration_minutes"))
                    .drop_column(Alias::new("lp_user_locked_message"))
                    .to_owned(),
            )
            .await
    }
}
