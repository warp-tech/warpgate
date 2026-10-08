use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use warpgate_common::{Secret, SecretError, SecretRef, SecretResolver};
use warpgate_common_cache::Cache;
use warpgate_db_entities::SecretBackend;
use warpgate_secrets_vault::VaultBackend;

use crate::logging::AuditEvent;

/// Resolves references against the backends stored in the database.
pub struct SecretBackendRegistry {
    db: DatabaseConnection,
    // Key = backend name
    clients: Cache<String, SecretBackend::Model, Arc<VaultBackend>>,
}

impl SecretBackendRegistry {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            db,
            clients: Cache::new(Duration::MAX),
        }
    }

    async fn get(&self, name: &str) -> Result<Arc<VaultBackend>, SecretError> {
        let row = SecretBackend::Entity::find()
            .filter(SecretBackend::Column::Name.eq(name))
            .one(&self.db)
            .await
            .map_err(|e| SecretError::Backend(e.to_string()))?
            .ok_or_else(|| SecretError::BackendNotConfigured {
                backend: name.to_owned(),
            })?;

        self.clients
            .get_or_build(&row.name, &row, || async {
                Ok(Arc::new(VaultBackend::new(&row.config()).await?))
            })
            .await
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
