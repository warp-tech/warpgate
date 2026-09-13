use std::path::PathBuf;

use sea_orm::entity::prelude::*;
use uuid::Uuid;
use warpgate_common::encryption::idempotent_maybe_decrypt;
use warpgate_common::{
    BackendType, Secret, SecretBackendConfig, VaultAuthConfig, VaultAuthMethod, VaultTlsConfig,
    WarpgateError, DEFAULT_KUBERNETES_JWT_PATH,
};

/// A Vault / OpenBao server that `vault://` / `openbao://` references resolve
/// against. Not serializable: API responses use their own DTO so the token and
/// AppRole secret never leave the row.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "secret_backends")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// The `backend` segment of references; see `validate_backend_name`.
    #[sea_orm(unique)]
    pub name: String,
    pub backend_type: String,
    #[sea_orm(column_type = "Text")]
    pub address: String,
    pub namespace: Option<String>,
    pub auth_method: String,
    /// Empty means the method's default mount.
    pub auth_mount: String,
    /// Encrypted at rest
    #[sea_orm(column_type = "Text", nullable)]
    pub token: Option<String>,
    pub app_role_id: Option<String>,
    /// Encrypted at rest
    #[sea_orm(column_type = "Text", nullable)]
    pub app_role_secret_id: Option<String>,
    pub kubernetes_role: Option<String>,
    pub tls_skip_verify: bool,
    /// One `mount/path` prefix per line; empty allows every path.
    #[sea_orm(column_type = "Text")]
    pub allowed_paths: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub fn allowed_paths(&self) -> Vec<String> {
        self.allowed_paths
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect()
    }

    pub fn backend_type(&self) -> Result<BackendType, WarpgateError> {
        Ok(self.backend_type.parse()?)
    }

    pub fn auth_method(&self) -> Result<VaultAuthMethod, WarpgateError> {
        Ok(self.auth_method.parse()?)
    }

    /// The runtime configuration, with the secret columns decrypted.
    pub fn config(&self) -> Result<SecretBackendConfig, WarpgateError> {
        let method = self.auth_method()?;
        let mount = if self.auth_mount.is_empty() {
            method.default_mount().to_owned()
        } else {
            self.auth_mount.clone()
        };
        let missing = |what: &str| {
            WarpgateError::InconsistentState(format!(
                "secret backend '{}' has no {what}",
                self.name
            ))
        };
        let auth = match method {
            VaultAuthMethod::Token => VaultAuthConfig::Token {
                token: Secret::new(idempotent_maybe_decrypt(
                    self.token.as_deref().ok_or_else(|| missing("token"))?,
                )?),
            },
            VaultAuthMethod::AppRole => VaultAuthConfig::AppRole {
                role_id: self
                    .app_role_id
                    .clone()
                    .ok_or_else(|| missing("AppRole role ID"))?,
                secret_id: Secret::new(idempotent_maybe_decrypt(
                    self.app_role_secret_id
                        .as_deref()
                        .ok_or_else(|| missing("AppRole secret ID"))?,
                )?),
                mount,
            },
            VaultAuthMethod::Kubernetes => VaultAuthConfig::Kubernetes {
                role: self
                    .kubernetes_role
                    .clone()
                    .ok_or_else(|| missing("Kubernetes role"))?,
                jwt_path: PathBuf::from(DEFAULT_KUBERNETES_JWT_PATH),
                mount,
            },
        };
        Ok(SecretBackendConfig {
            name: self.name.clone(),
            backend_type: self.backend_type()?,
            address: self.address.clone(),
            namespace: self.namespace.clone(),
            auth,
            tls: VaultTlsConfig {
                skip_verify: self.tls_skip_verify,
            },
            allowed_paths: self.allowed_paths(),
        })
    }
}
