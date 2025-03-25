use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use config::{Config, Environment, File, FileFormat};
use notify::{recommended_watcher, RecursiveMode, Watcher};
use tokio::sync::{broadcast, mpsc, Mutex};
use tracing::*;
use warpgate_common::helpers::fs::secure_file;
use warpgate_common::{WarpgateConfig, WarpgateConfigStore};

pub fn load_config(path: &Path, secure: bool) -> Result<WarpgateConfig> {
    let mut store: serde_yaml::Value = Config::builder()
        .add_source(File::new(path, FileFormat::Yaml))
        .add_source(Environment::with_prefix("WARPGATE"))
        .build()
        .context("Could not load config")?
        .try_deserialize()
        .context("Could not parse YAML")?;

    if secure {
        secure_file(path).context("Could not secure config")?;
    }

    check_and_migrate_config(&mut store);

    let store: WarpgateConfigStore =
        serde_yaml::from_value(store).context("Could not load config")?;

    let config = WarpgateConfig {
        store,
        paths_relative_to: path.parent().context("FS root reached")?.to_path_buf(),
    };

    info!("Using config: {path:?}");
    config.validate();
    Ok(config)
}

fn check_and_migrate_config(store: &mut serde_yaml::Value) {
    use serde_yaml::Value;
    if let Some(map) = store.as_mapping_mut() {
        if let Some(web_admin) = map.remove(Value::String("web_admin".into())) {
            warn!("The `web_admin` config section is deprecated. Rename it to `http`.");
            map.insert(Value::String("http".into()), web_admin);
        }

        if let Some(Value::Sequence(ref mut users)) = map.get_mut(Value::String("users".into())) {
            for user in users {
                if let Value::Mapping(ref mut user) = user {
                    if let Some(new_require) = match user.get(Value::String("require".into())) {
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

pub fn watch_config<P: AsRef<Path> + Send + 'static>(
    path: P,
    config: Arc<Mutex<WarpgateConfig>>,
) -> Result<broadcast::Receiver<()>> {
    let (tx, mut rx) = mpsc::channel(16);
    let mut watcher = recommended_watcher(move |res| {
        let _ = tx.blocking_send(res);
    })?;
    watcher.watch(path.as_ref(), RecursiveMode::NonRecursive)?;

    let path = PathBuf::from(path.as_ref());
    let (tx2, rx2) = broadcast::channel(16);
    tokio::spawn(async move {
        let _watcher = watcher; // avoid dropping the watcher
        loop {
            match rx.recv().await {
                Some(Ok(event)) => {
                    if event.kind.is_modify() {
                        match load_config(&path, false) {
                            Ok(new_config) => {
                                *(config.lock().await) = new_config;
                                let _ = tx2.send(());
                                info!("Reloaded config");
                            }
                            Err(error) => error!(?error, "Failed to reload config"),
                        }
                    }
                }
                Some(Err(error)) => error!(?error, "Failed to watch config"),
                None => {
                    error!("Config watch failed");
                    break;
                }
            }
        }

        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    });

    Ok(rx2)
}
