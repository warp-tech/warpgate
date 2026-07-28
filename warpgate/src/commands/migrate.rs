use anyhow::Result;
use tracing::info;
use warpgate_common::GlobalParams;
use warpgate_core::db::{connect_to_db, migrate_down, migrate_up};
use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};

use crate::config::load_config;

pub async fn command(params: &GlobalParams, steps: i32) -> Result<()> {
    let config = load_config(params, true)?;
    let connection = connect_to_db(&config, params).await?;

    // So the migrations can copy the settings that moved out of the config file.
    let recordings = config.store.recordings.clone().unwrap_or_default();
    set_config_migration_values(ConfigMigrationValues {
        recordings_enable: recordings.enable,
        recordings_path: recordings.path,
        ssh_host_key_verification: config.store.ssh.host_key_verification.into(),
    });

    let steps_abs = steps.unsigned_abs();
    if steps < 0 {
        info!("Reverting {steps_abs} migration(s)");
        migrate_down(&connection, steps_abs).await?;
    } else {
        info!("Applying {steps_abs} migration(s)");
        migrate_up(&connection, steps_abs).await?;
    }

    Ok(())
}
