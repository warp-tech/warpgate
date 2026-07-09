use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;
use tracing::{error, info};
use warpgate_common::{
    BackendType, SecretBackend, SecretBackendRef, SecretError, SecretRef,
    SecretValue, SecretsConfig, WarpgateError,
};
use warpgate_secrets_vault::VaultBackend;

use crate::logging::AuditEvent;

pub struct SecretBackendRegistry {
    backends: RwLock<HashMap<String, SecretBackendRef>>,
}

impl SecretBackendRegistry {
    
    pub async fn from_config(config: &SecretsConfig) -> Result<Self, WarpgateError> {
        Ok(Self {
            backends: RwLock::new(Self::build_backends(config).await),
        })
    }

    async fn build_backends(config: &SecretsConfig) -> HashMap<String, SecretBackendRef> {
        let mut backends: HashMap<String, SecretBackendRef> = HashMap::new();

        for backend_config in &config.backends {
            if backend_config.name.contains('/') {
                error!(
                    name = %backend_config.name,
                    "Secret backend name contains '/', which is ambiguous with the backend/path \
                     separator in `scheme://backend/path` references; skipping. Rename the \
                     backend in `secrets.backends` to a name without '/'.",
                );
                continue;
            }

            if backends.contains_key(&backend_config.name) {
                error!(
                    name = %backend_config.name,
                    "Duplicate secret backend name; keeping the first definition and \
                     ignoring this one.",
                );
                continue;
            }

            let backend: SecretBackendRef = match backend_config.backend_type {
                BackendType::Vault | BackendType::OpenBao => {
                    match VaultBackend::new(backend_config).await {
                        Ok(b) => Arc::new(b),
                        Err(e) => {
                            error!(
                                name = %backend_config.name,
                                error = %e,
                                "Failed to initialise secret backend; skipping. \
                                 References to this backend will fail until it is fixed \
                                 and the config is reloaded.",
                            );
                            continue;
                        }
                    }
                }
            };

            info!(name = %backend_config.name, "Secret backend registered");
            backends.insert(backend_config.name.clone(), backend);
        }

        backends
    }

    async fn get(&self, name: &str) -> Option<SecretBackendRef> {
        self.backends.read().await.get(name).cloned()
    }
}

#[async_trait]
impl SecretBackend for SecretBackendRegistry {
    async fn resolve(&self, reference: &SecretRef) -> Result<SecretValue, SecretError> {
        let result = match self.get(&reference.backend).await {
            Some(b) => b.resolve(reference).await,
            None => Err(SecretError::BackendNotConfigured {
                backend: reference.backend.clone(),
            }),
        };

        AuditEvent::SecretResolved {
            backend: reference.backend.clone(),
            reference: reference.to_string(),
            success: result.is_ok(),
        }
        .emit();

        result
    }

    async fn store(
        &self,
        reference: &SecretRef,
        value: &SecretValue,
    ) -> Result<(), SecretError> {
        let result = match self.get(&reference.backend).await {
            Some(b) => b.store(reference, value).await,
            None => Err(SecretError::BackendNotConfigured {
                backend: reference.backend.clone(),
            }),
        };

        AuditEvent::SecretStored {
            backend: reference.backend.clone(),
            reference: reference.to_string(),
            success: result.is_ok(),
        }
        .emit();

        result
    }

    async fn health(&self) -> Result<(), SecretError> {
        let backends: Vec<(String, SecretBackendRef)> = self
            .backends
            .read()
            .await
            .iter()
            .map(|(name, backend)| (name.clone(), backend.clone()))
            .collect();

        let results = futures::future::join_all(backends.iter().map(|(name, backend)| async move {
            backend
                .health()
                .await
                .map_err(|e| format!("{name}: {e}"))
        }))
        .await;

        let errors: Vec<String> = results.into_iter().filter_map(Result::err).collect();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(SecretError::Backend(errors.join("; ")))
        }
    }

    async fn health_for(&self, name: &str) -> Result<(), SecretError> {
        match self.get(name).await {
            Some(backend) => backend.health().await,
            None => Err(SecretError::BackendNotConfigured {
                backend: name.to_string(),
            }),
        }
    }

    async fn reload(&self, config: &SecretsConfig) {
        let new_backends = Self::build_backends(config).await;
        *self.backends.write().await = new_backends;
        info!("Secret backends reloaded");
    }
}