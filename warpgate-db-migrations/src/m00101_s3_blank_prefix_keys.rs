use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

use crate::m00010_parameters::parameters;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// An S3 store with a blank key prefix holds its recordings under keys that
/// start with `/`, which is how a blank prefix used to be joined. A blank
/// prefix adds nothing to a key now, while `/` gives those same keys, so the
/// store keeps reading what it has already written. Returns whether the
/// config changed.
fn keep_leading_slash_keys(config: &mut serde_json::Value) -> bool {
    if config.get("kind").and_then(serde_json::Value::as_str) != Some("S3") {
        return false;
    }
    match config.get_mut("prefix") {
        Some(prefix) if prefix.as_str() == Some("") => {
            *prefix = "/".into();
            true
        }
        _ => false,
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let storage = Alias::new("recordings_storage");

        let select = Query::select()
            .column(storage.clone())
            .from(parameters::Entity)
            .to_owned();
        for row in db.query_all(&select).await? {
            let stored: String = row.try_get("", "recordings_storage")?;
            // An unreadable config is reported where it is loaded
            let Ok(mut config) = serde_json::from_str(&stored) else {
                continue;
            };
            if keep_leading_slash_keys(&mut config) {
                let update = Query::update()
                    .table(parameters::Entity)
                    .value(storage.clone(), config.to_string())
                    .to_owned();
                db.execute(&update).await?;
            }
        }
        Ok(())
    }

    // `/` reads the same objects with the old key join as with the new one
    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::keep_leading_slash_keys;

    #[test]
    fn a_blank_s3_prefix_becomes_a_slash() {
        let mut config = json!({"kind": "S3", "bucket": "b", "prefix": ""});
        assert!(keep_leading_slash_keys(&mut config));
        assert_eq!(config, json!({"kind": "S3", "bucket": "b", "prefix": "/"}));
    }

    #[test]
    fn other_configs_are_left_alone() {
        for config in [
            json!({"kind": "S3", "bucket": "b", "prefix": "recordings"}),
            json!({"kind": "Azure", "container": "c", "prefix": ""}),
            json!({"kind": "Disk", "path": "recordings"}),
        ] {
            let mut migrated = config.clone();
            assert!(!keep_leading_slash_keys(&mut migrated));
            assert_eq!(migrated, config);
        }
    }
}
