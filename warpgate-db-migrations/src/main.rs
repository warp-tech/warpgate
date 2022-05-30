use sea_orm_migration::prelude::*;
use warpgate_db_migrations::Migrator;

#[async_std::main]
async fn main() {
    cli::run_cli(Migrator).await;
}
