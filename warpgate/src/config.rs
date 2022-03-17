use anyhow::{Context, Result};
use config::{Config, Environment, File};
use std::path::Path;
use tracing::*;
use warpgate_common::helpers::fs::secure_file;
use warpgate_common::{WarpgateConfig, WarpgateConfigStore};

pub fn load_config(path: &Path) -> Result<WarpgateConfig> {
    secure_file(path)?;

    let store: WarpgateConfigStore = Config::builder()
        .add_source(File::from(path))
        .add_source(Environment::with_prefix("WARPGATE"))
        .build()?
        .try_deserialize()
        .context("Could not load config")?;

    let config = WarpgateConfig {
        store,
        paths_relative_to: path.parent().unwrap().to_path_buf(),
    };

    info!(
        "Using config: {path:?} (users: {}, targets: {}, roles: {})",
        config.store.users.len(),
        config.store.targets.len(),
        config.store.roles.len(),
    );
    Ok(config)
}
