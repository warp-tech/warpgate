use sea_schema::migration::*;
use warpgate_db_migrations::Migrator;

#[async_std::main]
async fn main() {
    cli::run_cli(Migrator).await;
}
