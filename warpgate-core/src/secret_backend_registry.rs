use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::{DatabaseConnection, EntityTrait};
use tokio::sync::Mutex;
use warpgate_common::{
    MaybeSecretRef, Secret, SecretError, SecretRef, SecretResolver, StoredSecret, TargetSecrets,
    WarpgateError,
};
use warpgate_db_entities::SecretBackend as SecretBackendEntity;
use warpgate_secrets_vault::VaultBackend;

use crate::logging::AuditEvent;

/// Resolves references against the backends stored in the database.
///
/// The row is re-read on every lookup (one indexed query per connection), so a
/// backend created or changed through any node's admin API is used by every
/// node on its next resolve, with no cross-node signalling. The connected
/// client is cached per name and rebuilt whenever the row differs from the one
/// it was built from.
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

    async fn get(&self, name: &str) -> Result<Option<Arc<VaultBackend>>, SecretError> {
        let rows = SecretBackendEntity::Entity::find()
            .all(&self.db)
            .await
            .map_err(|e| SecretError::Backend(e.to_string()))?;

        let mut cache = self.cache.lock().await;
        // Rows deleted since the last lookup take their client, and with it
        // the token renewal task, with them.
        cache.retain(|cached, _| rows.iter().any(|row| &row.name == cached));

        let Some(row) = rows.into_iter().find(|row| row.name == name) else {
            return Ok(None);
        };
        if let Some((cached, backend)) = cache.get(name)
            && *cached == row
        {
            return Ok(Some(backend.clone()));
        }

        let config = row
            .config()
            .map_err(|e| SecretError::Backend(e.to_string()))?;
        let backend = Arc::new(VaultBackend::new(&config).await?);
        cache.insert(name.to_owned(), (row, backend.clone()));
        Ok(Some(backend))
    }

    async fn get_configured(&self, name: &str) -> Result<Arc<VaultBackend>, SecretError> {
        self.get(name)
            .await?
            .ok_or_else(|| SecretError::BackendNotConfigured {
                backend: name.to_owned(),
            })
    }

    async fn get_for(&self, reference: &SecretRef) -> Result<Arc<VaultBackend>, SecretError> {
        let backend = self.get_configured(&reference.backend).await?;
        if backend.backend_type() != reference.scheme {
            return Err(SecretError::Backend(format!(
                "reference scheme '{}' does not match the '{}' backend '{}'",
                reference.scheme,
                backend.backend_type(),
                reference.backend
            )));
        }
        Ok(backend)
    }

    pub async fn health_of(&self, name: &str) -> Result<(), SecretError> {
        self.get_configured(name).await?.health().await
    }
}

#[async_trait]
impl SecretResolver for SecretBackendRegistry {
    async fn resolve(&self, reference: &SecretRef) -> Result<Secret<String>, SecretError> {
        let result = match self.get_for(reference).await {
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

    async fn health(&self) -> Result<(), SecretError> {
        let rows = SecretBackendEntity::Entity::find()
            .all(&self.db)
            .await
            .map_err(|e| SecretError::Backend(e.to_string()))?;

        let mut errors = Vec::new();
        for row in rows {
            if let Err(e) = self.health_of(&row.name).await {
                errors.push(format!("{}: {e}", row.name));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(SecretError::Backend(errors.join("; ")))
        }
    }
}

/// Replaces every reference among a target's credentials with the secret it
/// names, so whatever consumes the options afterwards only ever sees values.
pub async fn resolve_secrets<O: TargetSecrets>(
    options: &mut O,
    backend: &dyn SecretResolver,
) -> Result<(), WarpgateError> {
    for slot in options.secrets_mut() {
        if slot.as_reference().is_some() {
            let value = slot.resolve(backend).await?;
            *slot = MaybeSecretRef::Inline(StoredSecret::from(value.expose_secret().clone()));
        }
    }
    Ok(())
}
