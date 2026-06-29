use sea_orm::{ConnectionTrait, Statement};
use sea_orm_migration::prelude::*;

use crate::m00010_parameters::parameters;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00054_login_protection_params"
    }
}

fn add_column(column: ColumnDef) -> TableAlterStatement {
    Table::alter()
        .table(parameters::Entity)
        .add_column(column)
        .to_owned()
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let columns = [
            ColumnDef::new(Alias::new("login_protection_enabled"))
                .boolean()
                .not_null()
                .default(true)
                .to_owned(),
            ColumnDef::new(Alias::new("login_protection_retention_days"))
                .integer()
                .not_null()
                .default(30)
                .to_owned(),
            ColumnDef::new(Alias::new("lp_ip_max_attempts"))
                .integer()
                .not_null()
                .default(5)
                .to_owned(),
            ColumnDef::new(Alias::new("lp_ip_time_window_minutes"))
                .integer()
                .not_null()
                .default(15)
                .to_owned(),
            ColumnDef::new(Alias::new("lp_ip_base_block_duration_minutes"))
                .integer()
                .not_null()
                .default(30)
                .to_owned(),
            ColumnDef::new(Alias::new("lp_ip_block_duration_multiplier"))
                .double()
                .not_null()
                .default(2.0)
                .to_owned(),
            ColumnDef::new(Alias::new("lp_ip_max_block_duration_hours"))
                .integer()
                .not_null()
                .default(24)
                .to_owned(),
            ColumnDef::new(Alias::new("lp_ip_cooldown_reset_hours"))
                .integer()
                .not_null()
                .default(24)
                .to_owned(),
            ColumnDef::new(Alias::new("lp_user_max_attempts"))
                .integer()
                .not_null()
                .default(10)
                .to_owned(),
            ColumnDef::new(Alias::new("lp_user_time_window_minutes"))
                .integer()
                .not_null()
                .default(60)
                .to_owned(),
            ColumnDef::new(Alias::new("lp_user_auto_unlock"))
                .boolean()
                .not_null()
                .default(true)
                .to_owned(),
            ColumnDef::new(Alias::new("lp_user_lockout_duration_minutes"))
                .integer()
                .not_null()
                .default(60)
                .to_owned(),
            ColumnDef::new(Alias::new("lp_user_exempt_admins"))
                .boolean()
                .not_null()
                .default(true)
                .to_owned(),
        ];

        for column in columns {
            manager.alter_table(add_column(column)).await?;
        }

        // New single-user setups get protection enabled with auto-unlock (the
        // column defaults above). Existing multi-user installs default to
        // disabled, so an upgrade can't lock real accounts out before an admin
        // has reviewed the policy.
        let db = manager.get_connection();
        let backend = db.get_database_backend();
        let user_count: i64 = db
            .query_one(Statement::from_string(
                backend,
                "SELECT COUNT(*) FROM users".to_owned(),
            ))
            .await?
            .map(|row| row.try_get_by_index::<i64>(0))
            .transpose()?
            .unwrap_or(0);

        if user_count > 1 {
            let stmt = Query::update()
                .table(parameters::Entity)
                .value(Alias::new("login_protection_enabled"), false)
                .to_owned();
            db.execute(backend.build(&stmt)).await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let columns = [
            "login_protection_enabled",
            "login_protection_retention_days",
            "lp_ip_max_attempts",
            "lp_ip_time_window_minutes",
            "lp_ip_base_block_duration_minutes",
            "lp_ip_block_duration_multiplier",
            "lp_ip_max_block_duration_hours",
            "lp_ip_cooldown_reset_hours",
            "lp_user_max_attempts",
            "lp_user_time_window_minutes",
            "lp_user_auto_unlock",
            "lp_user_lockout_duration_minutes",
            "lp_user_exempt_admins",
        ];

        for column in columns {
            manager
                .alter_table(
                    Table::alter()
                        .table(parameters::Entity)
                        .drop_column(Alias::new(column))
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }
}
