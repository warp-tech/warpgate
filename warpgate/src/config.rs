use anyhow::{Context, Result};
use config::{Config, Environment, File};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::*;
use warpgate_common::helpers::fs::secure_file;
use warpgate_common::{WarpgateConfig, WarpgateConfigStore};

pub fn load_config(path: &Path, secure: bool) -> Result<WarpgateConfig> {
    if secure {
        secure_file(path).context("Could not secure config")?;
    }

    let store: WarpgateConfigStore = Config::builder()
        .add_source(File::from(path))
        .add_source(Environment::with_prefix("WARPGATE"))
        .build()
        .context("Could not load config")?
        .try_deserialize()
        .context("Could not parse config")?;

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

pub async fn watch_config<P: AsRef<Path>>(
    path: P,
    config: Arc<Mutex<WarpgateConfig>>,
) -> Result<()> {
    let (tx, mut rx) = mpsc::channel(1);
    let mut watcher = RecommendedWatcher::new(move |res| {
        tx.blocking_send(res).unwrap();
    })?;
    watcher.configure(notify::Config::PreciseEvents(true))?;
    watcher.watch(path.as_ref(), RecursiveMode::NonRecursive)?;

    loop {
        match rx.recv().await {
            Some(Ok(event)) => {
                if event.kind.is_modify() {
                    match load_config(path.as_ref(), false) {
                        Ok(new_config) => {
                            *(config.lock().await) = new_config;
                            info!("Reloaded config");
                        }
                        Err(error) => error!(?error, "Failed to reload config"),
                    }
                }
            }
            Some(Err(error)) => error!(?error, "Failed to watch config"),
            None => error!("Config watch failed"),
        }
    }
}
