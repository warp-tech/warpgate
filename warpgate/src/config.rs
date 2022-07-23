use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use config::{Config, Environment, File};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::{mpsc, Mutex};
use tracing::*;
use warpgate_common::helpers::fs::secure_file;
use warpgate_common::{WarpgateConfig, WarpgateConfigStore};

pub fn load_config(path: &Path, secure: bool) -> Result<WarpgateConfig> {
    if secure {
        secure_file(path).context("Could not secure config")?;
    }

    let mut store: serde_yaml::Value = Config::builder()
        .add_source(File::from(path))
        .add_source(Environment::with_prefix("WARPGATE"))
        .build()
        .context("Could not load config")?
        .try_deserialize()
        .context("Could not parse YAML")?;

    check_and_migrate_config(&mut store);

    let store: WarpgateConfigStore =
        serde_yaml::from_value(store).context("Could not load config")?;

    let config = WarpgateConfig {
        store,
        paths_relative_to: path.parent().context("FS root reached")?.to_path_buf(),
    };

    info!(
        "Using config: {path:?} (users: {}, targets: {}, roles: {})",
        config.store.users.len(),
        config.store.targets.len(),
        config.store.roles.len(),
    );
    Ok(config)
}

fn check_and_migrate_config(store: &mut serde_yaml::Value) {
    use serde_yaml::Value;
    if let Some(map) = store.as_mapping_mut() {
        if let Some(web_admin) = map.remove(&Value::String("web_admin".into())) {
            warn!("The `web_admin` config section is deprecated. Rename it to `http`.");
            map.insert(Value::String("http".into()), web_admin);
        }

        if let Some(Value::Sequence(ref mut users)) = map.get_mut(&Value::String("users".into())) {
            for user in users {
                if let Value::Mapping(ref mut user) = user {
                    if let Some(new_require) = match user.get(&Value::String("require".into())) {
                        Some(Value::Sequence(ref old_requires)) => Some(Value::Mapping(
                            vec![
                                (
                                    Value::String("ssh".into()),
                                    Value::Sequence(old_requires.clone()),
                                ),
                                (
                                    Value::String("http".into()),
                                    Value::Sequence(old_requires.clone()),
                                ),
                            ]
                            .into_iter()
                            .collect(),
                        )),
                        x => x.cloned(),
                    } {
                        user.insert(Value::String("require".into()), new_require);
                    }
                }
            }
        }
    }
}

pub async fn watch_config<P: AsRef<Path>>(
    path: P,
    config: Arc<Mutex<WarpgateConfig>>,
) -> Result<()> {
    let (tx, mut rx) = mpsc::channel(1);
    let mut watcher = RecommendedWatcher::new(move |res| {
        let _ = tx.blocking_send(res);
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
