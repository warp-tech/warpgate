use anyhow::Result;
use std::os::unix::fs::PermissionsExt;
use config::{Config, Environment, File};
use tracing::*;
use warpgate_common::WarpgateConfig;

pub fn load_config() -> Result<WarpgateConfig> {
    let path = "config.yaml";

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

    let config: WarpgateConfig = Config::builder()
        .add_source(File::with_name(path))
        .add_source(Environment::with_prefix("WARPGATE"))
        .build()?
        .try_deserialize()?;
    info!(
        "Using config: {path} (users: {}, targets: {})",
        config.users.len(),
        config.targets.len()
    );
    Ok(config)
}
