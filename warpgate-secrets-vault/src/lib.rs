use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use vaultrs::client::{Client, VaultClient, VaultClientSettingsBuilder};
use warpgate_common::{SecretBackend, SecretBackendConfig, SecretError, SecretRef, SecretValue};

type SecretDataMap = HashMap<String, serde_json::Value>;

pub struct VaultBackend {
    client: Arc<Mutex<VaultClient>>,
    auth_config: warpgate_common::VaultAuthConfig,
}

impl VaultBackend {

    pub async fn new(config: &SecretBackendConfig) -> Result<Self, SecretError> {
        let mut builder = VaultClientSettingsBuilder::default();
        builder.address(&config.address);

        if let Some(ns) = &config.namespace {
            builder.set_namespace(ns.clone());
        }

        builder.verify(!config.tls.skip_verify);

        if let Some(ca) = &config.tls.ca_cert {
            builder.ca_certs(vec![
                ca.to_string_lossy().into_owned(),
            ]);
        }

        let settings = builder
            .build()
            .map_err(|e| SecretError::Backend(format!("build Vault client: {e}")))?;

        let mut client = VaultClient::new(settings)
            .map_err(|e| SecretError::Backend(format!("create Vault client: {e}")))?;

        let initial_lease = match authenticate(&mut client, &config.auth).await {
            Ok(lease) => lease,
            Err(e) => {
                warn!(
                    address = %config.address,
                    name = %config.name,
                    error = %e,
                    "Vault backend could not authenticate at startup; \
                     it will retry in the background and on first use",
                );
                None
            }
        };

        let backend = Self {
            client: Arc::new(Mutex::new(client)),
            auth_config: config.auth.clone(),
        };

        backend.spawn_renewal_task(config.auth.clone(), initial_lease);

        info!(address = %config.address, name = %config.name, "Vault backend initialised");
        Ok(backend)
    }

    fn spawn_renewal_task(
        &self,
        auth: warpgate_common::VaultAuthConfig,
        initial_lease: Option<Duration>,
    ) {
        use warpgate_common::VaultAuthConfig;

        if matches!(auth, VaultAuthConfig::Token { .. }) {
            return;
        }

        let client = Arc::downgrade(&self.client);

        tokio::spawn(async move {
            let mut lease = initial_lease;
            loop {
                tokio::time::sleep(renewal_interval(lease)).await;

                let Some(client) = client.upgrade() else {
                    debug!("Vault backend dropped; stopping renewal task");
                    break;
                };
                let mut locked = client.lock().await;
                match authenticate(&mut locked, &auth).await {
                    Ok(new_lease) => {
                        debug!("Vault token renewed");
                        lease = new_lease;
                    }
                    Err(e) => {
                        error!("Vault token renewal failed: {e}");
                        // Drop back to the short retry cadence until renewal succeeds again.
                        lease = None;
                    }
                }
            }
        });
    }

    async fn fetch_from_vault(
        &self,
        mount: &str,
        kv_path: &str,
    ) -> Result<SecretDataMap, SecretError> {
        let client = self.client.lock().await;
        vaultrs::kv2::read::<SecretDataMap>(&*client, mount, kv_path)
            .await
            .map_err(|e| match e {
                vaultrs::error::ClientError::APIError { code: 404, .. } => SecretError::NotFound {
                    path: format!("{mount}/{kv_path}"),
                },
                other => SecretError::Backend(format!("KV v2 read {mount}/{kv_path}: {other}")),
            })
    }

    async fn fetch_with_version(
        &self,
        mount: &str,
        kv_path: &str,
    ) -> Result<(SecretDataMap, u64), SecretError> {
        use vaultrs::api::kv2::requests::ReadSecretRequest;

        let endpoint = ReadSecretRequest::builder()
            .mount(mount)
            .path(kv_path)
            .build()
            .expect("mount and path are always set");

        let client = self.client.lock().await;
        match vaultrs::api::exec_with_result(&*client, endpoint).await {
            Ok(res) => {
                let data = serde_json::from_value(res.data).map_err(|e| {
                    SecretError::Backend(format!("KV v2 read {mount}/{kv_path}: {e}"))
                })?;
                Ok((data, res.metadata.version))
            }
            Err(vaultrs::error::ClientError::APIError { code: 404, .. }) => {
                Ok((SecretDataMap::new(), 0))
            }
            Err(other) => Err(SecretError::Backend(format!(
                "KV v2 read {mount}/{kv_path}: {other}"
            ))),
        }
    }

    fn split_path<'a>(path: &'a str) -> Result<(&'a str, &'a str), SecretError> {
        path.split_once('/').ok_or_else(|| {
            SecretError::InvalidRef(format!(
                "path must be 'mount/kv_path', got '{path}'"
            ))
        })
    }
}

#[async_trait]
impl SecretBackend for VaultBackend {
    async fn resolve(&self, reference: &SecretRef) -> Result<SecretValue, SecretError> {
        let field = reference.field.as_deref().ok_or_else(|| {
            SecretError::InvalidRef(format!(
                "a #field is required for Vault references (got '{reference}')"
            ))
        })?;

        let (mount, kv_path) = Self::split_path(&reference.path)?;

        let data = match self.fetch_from_vault(mount, kv_path).await {
            Ok(d) => d,
            Err(e @ SecretError::NotFound { .. }) => return Err(e),
            Err(e) => {
                // On auth failure, try to re-authenticate once and retry.
                warn!("Vault read failed ({e}), attempting re-authentication");
                let mut locked = self.client.lock().await;
                authenticate(&mut locked, &self.auth_config).await?;
                drop(locked);
                self.fetch_from_vault(mount, kv_path).await?
            }
        };

        data.get(field)
            .map(|v| SecretValue::new(value_to_string(v)))
            .ok_or_else(|| SecretError::NotFound {
                path: reference.path.clone(),
            })
    }

    async fn store(&self, reference: &SecretRef, value: &SecretValue) -> Result<(), SecretError> {
        let field = reference.field.as_deref().ok_or_else(|| {
            SecretError::InvalidRef(format!(
                "a #field is required for Vault references (got '{reference}')"
            ))
        })?;

        let (mount, kv_path) = Self::split_path(&reference.path)?;

        use vaultrs::api::kv2::requests::SetSecretRequestOptions;

        const MAX_ATTEMPTS: u32 = 10;
        let mut reauthenticated = false;

        for attempt in 0..MAX_ATTEMPTS {
            let (mut data, version) = match self.fetch_with_version(mount, kv_path).await {
                Ok(v) => v,
                Err(e) if !reauthenticated => {
                    // On auth failure, try to re-authenticate once and retry.
                    warn!("Vault read failed ({e}), attempting re-authentication");
                    let mut locked = self.client.lock().await;
                    authenticate(&mut locked, &self.auth_config).await?;
                    drop(locked);
                    reauthenticated = true;
                    self.fetch_with_version(mount, kv_path).await?
                }
                Err(e) => return Err(e),
            };

            data.insert(
                field.to_string(),
                serde_json::Value::String(value.expose().to_string()),
            );

            let options = SetSecretRequestOptions {
                cas: u32::try_from(version).unwrap_or(u32::MAX),
            };

            let result = {
                let client = self.client.lock().await;
                vaultrs::kv2::set_with_options(&*client, mount, kv_path, &data, options).await
            };

            match result {
                Ok(_) => return Ok(()),
                Err(vaultrs::error::ClientError::APIError { code: 400, errors })
                    if errors
                        .iter()
                        .any(|e| e.to_lowercase().contains("check-and-set")) =>
                {
                    debug!(
                        attempt,
                        "Vault CAS conflict writing {mount}/{kv_path}, retrying with fresh data"
                    );
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    continue;
                }
                Err(e) => {
                    return Err(SecretError::Backend(format!(
                        "KV v2 write {mount}/{kv_path}: {e}"
                    )))
                }
            }
        }

        Err(SecretError::Backend(format!(
            "KV v2 write {mount}/{kv_path}: gave up after {MAX_ATTEMPTS} attempts due to concurrent writers"
        )))
    }

    async fn health(&self) -> Result<(), SecretError> {
        let client = self.client.lock().await;
        let status = Client::status(&*client)
            .await
            .map_err(|e| SecretError::Backend(format!("health check: {e}")))?;

        use vaultrs::sys::ServerStatus;
        match status {
            ServerStatus::OK | ServerStatus::STANDBY | ServerStatus::PERFSTANDBY => Ok(()),
            other => Err(SecretError::Backend(format!(
                "Vault is not ready: {other:?}"
            ))),
        }
    }
}

fn value_to_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn renewal_interval(lease: Option<Duration>) -> Duration {
    const MIN: Duration = Duration::from_secs(30);
    const FALLBACK: Duration = Duration::from_secs(60);
    match lease {
        Some(l) if !l.is_zero() => l.mul_f64(0.75).max(MIN).min(l),
        _ => FALLBACK,
    }
}

async fn authenticate(
    client: &mut VaultClient,
    auth: &warpgate_common::VaultAuthConfig,
) -> Result<Option<Duration>, SecretError> {
    use warpgate_common::VaultAuthConfig;

    match auth {
        VaultAuthConfig::Token { token } => {
            client.set_token(token.expose_secret());
            Ok(None)
        }
        VaultAuthConfig::AppRole {
            role_id_file,
            secret_id_file,
            mount,
        } => {
            let role_id = tokio::fs::read_to_string(role_id_file).await.map_err(|e| {
                SecretError::Backend(format!(
                    "read role_id from {}: {e}",
                    role_id_file.display()
                ))
            })?;
            let secret_id =
                tokio::fs::read_to_string(secret_id_file)
                    .await
                    .map_err(|e| {
                        SecretError::Backend(format!(
                            "read secret_id from {}: {e}",
                            secret_id_file.display()
                        ))
                    })?;

            let info = vaultrs::auth::approle::login(
                client,
                mount,
                role_id.trim(),
                secret_id.trim(),
            )
            .await
            .map_err(|e| SecretError::Backend(format!("AppRole login: {e}")))?;

            client.set_token(&info.client_token);
            Ok(Some(Duration::from_secs(info.lease_duration)))
        }
        VaultAuthConfig::Kubernetes { role, jwt_path, mount } => {
            let jwt = tokio::fs::read_to_string(jwt_path).await.map_err(|e| {
                SecretError::Backend(format!("read JWT from {}: {e}", jwt_path.display()))
            })?;

            let info =
                vaultrs::auth::kubernetes::login(client, mount, role, jwt.trim())
                    .await
                    .map_err(|e| SecretError::Backend(format!("Kubernetes login: {e}")))?;

            client.set_token(&info.client_token);
            Ok(Some(Duration::from_secs(info.lease_duration)))
        }
    }
}
