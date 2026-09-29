use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::{DatabaseConnection, EntityTrait};
use tokio::sync::Mutex;
use warpgate_common::{Secret, SecretError, SecretRef, SecretResolver};
use warpgate_db_entities::SecretBackend;
use warpgate_secrets_vault::VaultBackend;

use crate::logging::AuditEvent;

/// Resolves references against the backends stored in the database.
pub struct SecretBackendRegistry {
    db: DatabaseConnection,
    // Caches clients for as long as the config does not change
    cache: Mutex<HashMap<String, (SecretBackend::Model, Arc<VaultBackend>)>>,
}

impl SecretBackendRegistry {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            db,
            cache: Mutex::new(HashMap::new()),
        }
    }

    async fn get(&self, name: &str) -> Result<Arc<VaultBackend>, SecretError> {
        let rows = SecretBackend::Entity::find()
            .all(&self.db)
            .await
            .map_err(|e| SecretError::Backend(e.to_string()))?;

        let mut cache = self.cache.lock().await;
        // Drop clients for deleted configs
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
        let backend = self.get(&reference.backend).await?;
        let result = backend.resolve(reference).await;

        AuditEvent::SecretResolved {
            backend: reference.backend.clone(),
            reference: reference.to_string(),
            success: result.is_ok(),
        }
        .emit();

        result
    }
}
