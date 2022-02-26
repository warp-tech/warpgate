pub mod models;
pub mod schema;
pub mod uuid;

use anyhow::{Result, Context};
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::sqlite::SqliteConnection;
use diesel_migrations::embed_migrations;
use std::path::Path;

use crate::WarpgateConfig;

embed_migrations!("../migrations");

pub type DatabasePool = Pool<ConnectionManager<SqliteConnection>>;

pub fn connect_to_db(config: &WarpgateConfig) -> Result<DatabasePool> {
    if config.database_url.ends_with(".sqlite3") {
        if let Some(parent) = Path::new(&config.database_url).parent() {
            std::fs::create_dir_all(parent)?
        }
    }
    let manager = ConnectionManager::<SqliteConnection>::new(&config.database_url);
    let pool = Pool::builder().build(manager).context("Connection failed")?;
    let connection = pool.get()?;
    embedded_migrations::run_with_output(&connection, &mut std::io::stdout()).context("Migration failed")?;
    Ok(pool)
}
