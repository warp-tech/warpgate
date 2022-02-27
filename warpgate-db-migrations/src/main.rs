use warpgate_db_migrations::Migrator;
use sea_schema::migration::*;

#[async_std::main]
async fn main() {
    cli::run_cli(Migrator).await;
}
