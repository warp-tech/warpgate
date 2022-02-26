use anyhow::Result;
use tracing::*;
use config::{Config, Environment, File};
use warpgate_common::WarpgateConfig;

pub fn load_config() -> Result<WarpgateConfig> {
    let path = "config.yaml";
    let config: WarpgateConfig = Config::builder()
        .add_source(File::with_name(path))
        .add_source(Environment::with_prefix("WARPGATE"))
        .build()?.try_deserialize()?;
    info!("Using config: {path} (users: {}, targets: {})", config.users.len(), config.targets.len());
    Ok(config)
}
