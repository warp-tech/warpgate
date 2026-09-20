use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::{DatabaseConnection, EntityTrait};
use tokio::sync::Mutex;
use warpgate_common::{Secret, SecretError, SecretRef, SecretResolver};
use warpgate_db_entities::SecretBackend as SecretBackendEntity;
use warpgate_secrets_vault::VaultBackend;

use crate::logging::AuditEvent;

/// Resolves references against the backends stored in the database.
///
/// The table is re-read on every lookup, so a backend created or changed
/// through any node's admin API is used by every node on its next resolve,
/// with no cross-node signalling. The connected client is cached per name and
/// rebuilt whenever the row differs from the one it was built from.
pub struct SecretBackendRegistry {
    db: DatabaseConnection,
    // ponytail: one lock across the whole cache, held while a backend connects.
    // Per-name locks if connect-time contention ever shows up.
    cache: Mutex<HashMap<String, (SecretBackendEntity::Model, Arc<VaultBackend>)>>,
}

impl SecretBackendRegistry {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            db,
            cache: Mutex::new(HashMap::new()),
        }
    }

    async fn get(&self, name: &str) -> Result<Arc<VaultBackend>, SecretError> {
        let rows = SecretBackendEntity::Entity::find()
            .all(&self.db)
            .await
            .map_err(|e| SecretError::Backend(e.to_string()))?;

        let mut cache = self.cache.lock().await;
        // Rows deleted since the last lookup take their client, and with it
        // the token renewal task, with them.
        cache.retain(|cached, _| rows.iter().any(|row| &row.name == cached));

        let Some(row) = rows.into_iter().find(|row| row.name == name) else {
            return Err(SecretError::BackendNotConfigured {
                backend: name.to_owned(),
            });
        };
        if let Some((cached, backend)) = cache.get(name)
            && *cached == row
        {
            return Ok(backend.clone());
        }

        let backend = Arc::new(VaultBackend::new(&row.config()).await?);
        cache.insert(name.to_owned(), (row, backend.clone()));
        Ok(backend)
    }

    pub async fn health_of(&self, name: &str) -> Result<(), SecretError> {
        self.get(name).await?.health().await
    }
}

#[async_trait]
impl SecretResolver for SecretBackendRegistry {
    async fn resolve(&self, reference: &SecretRef) -> Result<Secret<String>, SecretError> {
        let result = match self.get(&reference.backend).await {
            Ok(backend) => backend.resolve(reference).await,
            Err(e) => Err(e),
        };

        AuditEvent::SecretResolved {
            backend: reference.backend.clone(),
            reference: reference.to_string(),
            success: result.is_ok(),
        }
        .emit();

        result
    }
}
