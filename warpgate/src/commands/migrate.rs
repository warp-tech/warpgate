use anyhow::Result;
use tracing::info;
use warpgate_common::GlobalParams;
use warpgate_core::db::{connect_to_db, migrate_down, migrate_up};

use crate::config::load_config;

pub async fn command(params: &GlobalParams, steps: i32) -> Result<()> {
    let config = load_config(params, true)?;
    let connection = connect_to_db(&config, params).await?;

    if steps < 0 {
        let steps = steps.unsigned_abs();
        info!("Reverting {steps} migration(s)");
        migrate_down(&connection, steps).await?;
    } else {
        let steps = steps.unsigned_abs();
        info!("Applying {steps} migration(s)");
        migrate_up(&connection, steps).await?;
    }

    Ok(())
}
