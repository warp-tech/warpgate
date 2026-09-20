use sea_orm::entity::prelude::*;
use uuid::Uuid;
use warpgate_common::{BackendType, SecretBackendConfig, VaultAuthConfig};

/// A Vault / OpenBao server that `secret://` references resolve against.
/// Not serializable: API responses use their own DTO so the login secret
/// never leaves the row.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "secret_backends")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// The `backend` segment of references; see `validate_backend_name`.
    #[sea_orm(unique)]
    pub name: String,
    pub backend_type: BackendType,
    #[sea_orm(column_type = "Text")]
    pub address: String,
    pub namespace: Option<String>,
    #[sea_orm(column_type = "Json")]
    pub auth: VaultAuthConfig,
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

    pub fn config(&self) -> SecretBackendConfig {
        SecretBackendConfig {
            name: self.name.clone(),
            address: self.address.clone(),
            namespace: self.namespace.clone(),
            auth: self.auth.clone(),
            tls_skip_verify: self.tls_skip_verify,
            allowed_paths: self.allowed_paths(),
        }
    }
}
