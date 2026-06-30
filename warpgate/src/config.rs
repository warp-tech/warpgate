use std::sync::Arc;

use anyhow::{Context, Result};
use config::{Config, Environment, File, FileFormat};
use notify::{RecursiveMode, Watcher, recommended_watcher};
use tokio::sync::{Mutex, broadcast, mpsc};
use tracing::{error, info, warn};
use warpgate_common::helpers::fs::secure_file;
use warpgate_common::{GlobalParams, WarpgateConfig, WarpgateConfigStore};

pub fn load_config(params: &GlobalParams, secure: bool) -> Result<WarpgateConfig> {
    let mut store: serde_yaml::Value = Config::builder()
        .add_source(File::new(
            params
                .config_path()
                .to_str()
                .context("Invalid config path")?,
            FileFormat::Yaml,
        ))
        .add_source(Environment::with_prefix("WARPGATE"))
        .build()
        .context("Could not load config")?
        .try_deserialize()
        .context("Could not parse YAML")?;

    if secure && params.should_secure_files() {
        secure_file(params.config_path()).context("Could not secure config")?;
    }

    check_and_migrate_config(&mut store);

    // Deserialize via serde_ignored so that unknown / misplaced keys are
    // surfaced instead of silently dropped. Warpgate's config structs do not
    // use `deny_unknown_fields`, so a typo'd or wrongly-nested key (e.g.
    // `role_mappings` placed on the sso_providers entry instead of under
    // `provider`, or `log.retention_days` instead of `log.retention`) would
    // otherwise parse green and have no effect — and `warpgate check` could not
    // catch it. We keep loading (non-breaking) but warn with the full path of
    // each ignored key.
    let (store, ignored_keys) =
        deserialize_store_collecting_ignored(store).context("Could not load config")?;
    for path in &ignored_keys {
        warn!(
            "Ignoring unknown config key `{path}` — likely a typo or a misplaced key; it has NO effect"
        );
    }

    let config = WarpgateConfig { store };

    info!("Using config: {:?}", params.config_path());
    config.validate();
    Ok(config)
}

/// Deserialize the merged config value into the typed store, collecting the
/// dotted paths of any keys Warpgate does not recognise. Because the config
/// structs have no `deny_unknown_fields`, such keys are otherwise silently
/// dropped; we record them so the caller can warn instead.
fn deserialize_store_collecting_ignored(
    value: serde_yaml::Value,
) -> Result<(WarpgateConfigStore, Vec<String>), serde_yaml::Error> {
    use serde::de::IntoDeserializer;
    let mut ignored = vec![];
    let store = serde_ignored::deserialize(
        IntoDeserializer::<serde_yaml::Error>::into_deserializer(value),
        |path| ignored.push(path.to_string()),
    )?;
    Ok((store, ignored))
}

fn check_and_migrate_config(store: &mut serde_yaml::Value) {
    use serde_yaml::Value;
    if let Some(map) = store.as_mapping_mut() {
        if let Some(web_admin) = map.remove(Value::String("web_admin".into())) {
            warn!("The `web_admin` config section is deprecated. Rename it to `http`.");
            map.insert(Value::String("http".into()), web_admin);
        }

        if let Some(Value::Sequence(users)) = map.get_mut(Value::String("users".into())) {
            for user in users {
                if let Value::Mapping(user) = user
                    && let Some(new_require) = match user.get(Value::String("require".into())) {
                        Some(Value::Sequence(old_requires)) => Some(Value::Mapping(
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
                    }
                {
                    user.insert(Value::String("require".into()), new_require);
                }
            }
        }
    }
}

pub fn watch_config(
    params: &GlobalParams,
    config: Arc<Mutex<WarpgateConfig>>,
) -> Result<broadcast::Receiver<()>> {
    let params = params.clone();

    let (tx, mut rx) = mpsc::channel(16);
    let mut watcher = recommended_watcher(move |res| {
        let _ = tx.blocking_send(res);
    })?;
    watcher.watch(params.config_path().as_ref(), RecursiveMode::NonRecursive)?;

    let (tx2, rx2) = broadcast::channel(16);
    tokio::spawn(async move {
        let _watcher = watcher; // avoid dropping the watcher
        loop {
            match rx.recv().await {
                Some(Ok(event)) => {
                    if event.kind.is_modify() {
                        match load_config(&params, false) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> (WarpgateConfigStore, Vec<String>) {
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        deserialize_store_collecting_ignored(value).unwrap()
    }

    #[test]
    fn known_keys_produce_no_ignored_paths() {
        let (_store, ignored) =
            parse("external_host: bastion.example\nhttp:\n  listen: \"0.0.0.0:8888\"\n");
        assert!(ignored.is_empty(), "unexpected ignored keys: {ignored:?}");
    }

    #[test]
    fn reports_unknown_top_level_key() {
        let (_store, ignored) = parse("external_host: x\nbogus_key: 1\n");
        assert_eq!(ignored, vec!["bogus_key".to_string()]);
    }

    #[test]
    fn reports_misplaced_nested_key_with_full_path() {
        // role_mappings belongs UNDER `provider:`, not on the sso_providers entry.
        // Misplaced here it is silently ignored, so SSO users get no roles.
        let yaml = "
sso_providers:
  - name: keycloak
    provider:
      type: custom
      client_id: warpgate
      client_secret: secret
      issuer_url: https://id.example/realms/x
      scopes: [openid]
    role_mappings:
      admins: warpgate:admin
";
        let (_store, ignored) = parse(yaml);
        assert!(
            ignored.iter().any(|p| p.contains("role_mappings")),
            "expected the misplaced role_mappings to be reported, got {ignored:?}"
        );
    }
}
