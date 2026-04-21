use sea_orm::prelude::*;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, JsonValue, QueryFilter, Set};
use sea_orm_migration::prelude::*;

use crate::m00007_targets_and_roles::target;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00037_target_ssh_cert"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();

        // Find SSH targets
        let ssh_targets = target::Entity::find()
            .filter(target::Column::Kind.eq(target::TargetKind::Ssh))
            .all(conn)
            .await?;

        for target in ssh_targets {
            let mut options = target
                .options
                .get("ssh")
                .unwrap_or(Default::default())
                .clone();

            if let Some(auth) = options.get_mut("auth") {
                if auth.get("kind").is_some() {
                    continue;
                } else if let Some(password) = auth.get("password").cloned() {
                    *auth = serde_json::json!({
                        "kind": "password",
                        "password": password,
                    });
                } else {
                    *auth = serde_json::json!({
                        "kind": "publickey",
                    });
                }

                let mut target: target::ActiveModel = target.into();
                let options = serde_json::json!({"ssh": options});
                target.options = Set(options);
                target.update(conn).await?;
            }
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();

        // Find SSH targets
        let ssh_targets = target::Entity::find()
            .filter(target::Column::Kind.eq(target::TargetKind::Ssh))
            .all(conn)
            .await?;

        // Check if there is a target authenticated by a certificate
        let has_certificates = ssh_targets
            .iter()
            .filter_map(|t| t.options.get("ssh"))
            .filter_map(|t| t.get("auth"))
            .any(|t| {
                let value = JsonValue::String("certificate".to_string());
                t.get("kind") == Some(&value)
            });

        if has_certificates {
            // At least one target is using certificate auth
            // reversing would fallback to pubkey, which would not work
            panic!("This migration cannot be reversed");
        }

        for target in ssh_targets {
            let mut options = target
                .options
                .get("ssh")
                .unwrap_or(Default::default())
                .clone();

            if let Some(auth) = options.get_mut("auth") {
                if let Some(password) = auth.get("password").cloned() {
                    *auth = serde_json::json!({
                        "password": password,
                    });
                } else {
                    *auth = serde_json::json!({});
                }

                let mut target: target::ActiveModel = target.into();
                let options = serde_json::json!({"ssh": options});
                target.options = Set(options);
                target.update(conn).await?;
            }
        }
        Ok(())
    }
}
