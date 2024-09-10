use std::sync::Arc;

use russh::keys::key::PublicKey;
use russh::keys::PublicKeyBase64;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_db_entities::KnownHost;

pub struct KnownHosts {
    db: Arc<Mutex<DatabaseConnection>>,
}

pub enum KnownHostValidationResult {
    Valid,
    Invalid {
        key_type: String,
        key_base64: String,
    },
    Unknown,
}

impl KnownHosts {
    pub fn new(db: &Arc<Mutex<DatabaseConnection>>) -> Self {
        Self { db: db.clone() }
    }

    pub async fn validate(
        &mut self,
        host: &str,
        port: u16,
        key: &PublicKey,
    ) -> Result<KnownHostValidationResult, sea_orm::DbErr> {
        let db = self.db.lock().await;
        let entries = KnownHost::Entity::find()
            .filter(KnownHost::Column::Host.eq(host))
            .filter(KnownHost::Column::Port.eq(port))
            .filter(KnownHost::Column::KeyType.eq(key.name()))
            .all(&*db)
            .await?;

        let key_base64 = key.public_key_base64();
        if entries.iter().any(|x| x.key_base64 == key_base64) {
            return Ok(KnownHostValidationResult::Valid);
        }
        if let Some(first) = entries.first() {
            return Ok(KnownHostValidationResult::Invalid {
                key_type: first.key_type.clone(),
                key_base64: first.key_base64.clone(),
            });
        }
        Ok(KnownHostValidationResult::Unknown)
    }

    pub async fn trust(
        &mut self,
        host: &str,
        port: u16,
        key: &PublicKey,
    ) -> Result<(), sea_orm::DbErr> {
        use sea_orm::ActiveValue::Set;

        let values = KnownHost::ActiveModel {
            id: Set(Uuid::new_v4()),
            host: Set(host.to_owned()),
            port: Set(port.into()),
            key_type: Set(key.name().to_owned()),
            key_base64: Set(key.public_key_base64()),
        };

        let db = self.db.lock().await;
        values.insert(&*db).await?;

        Ok(())
    }
}
