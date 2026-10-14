use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info, warn};
use vaultrs::api::ssh::requests::SignSSHKeyRequest;
use vaultrs::api::ssh::responses::SignSSHKeyResponse;
use vaultrs::client::{Client, VaultClient, VaultClientSettingsBuilder};
use vaultrs::error::ClientError;
use warpgate_common::{
    Secret, SecretBackendConfig, SecretError, SecretRef, SecretResolver, StoredSecret,
    VaultAppRoleAuth, VaultAuthConfig, VaultKubernetesAuth, VaultTokenAuth,
};

type SecretDataMap = std::collections::HashMap<String, serde_json::Value>;

/// Bounds every Vault round-trip so a stalled server fails a connection
/// attempt instead of holding it (and everything queued behind it) forever.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// A denied read triggers one re-login; further denials within this window
/// are reported as-is, so a misconfigured policy can't burn AppRole secret-id
/// uses or pile up tokens at connection rate.
const REAUTH_MIN_INTERVAL: Duration = Duration::from_secs(30);
/// Where a pod's service account token is mounted.
const KUBERNETES_JWT_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
/// The target's sshd logs the certificate key ID verbatim; this keeps a long
/// username from flooding that log.
const MAX_SSH_KEY_ID: usize = 256;
/// Without it, a role that sets no `ttl` signs for the mount's default, 768h.
const CERTIFICATE_TTL: &str = "5m";

pub struct VaultBackend {
    name: String,
    /// Readers share the client; only (re)authentication takes the write lock.
    client: Arc<RwLock<VaultClient>>,
    auth_config: VaultAuthConfig,
    /// Path prefixes this backend may be asked for, from the config, empty =
    /// any: `mount/path` for a KV read, `mount/sign/role` for SSH signing.
    allowed_paths: Vec<String>,
    last_reauth: Mutex<Option<Instant>>,
}

impl VaultBackend {
    pub async fn new(config: &SecretBackendConfig) -> Result<Self, SecretError> {
        if !config.address.starts_with("https://") {
            warn!(
                address = %config.address,
                name = %config.name,
                "Vault backend address is not https; the token is sent in clear",
            );
        }

        let mut builder = VaultClientSettingsBuilder::default();
        builder.address(&config.address);
        builder.timeout(Some(REQUEST_TIMEOUT));
        // Set explicitly so vaultrs does not fall back to VAULT_TOKEN / VAULT_CACERT /
        // VAULT_CAPATH from the environment.
        builder.token("");
        builder.ca_certs(Vec::new());

        if let Some(ns) = &config.namespace {
            builder.set_namespace(ns.clone());
        }

        builder.verify(!config.tls_skip_verify);

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

        let renewal = match &config.auth {
            VaultAuthConfig::Token(_) => renewable_token_ttl(&client, &config.name).await,
            _ => Some(initial_lease),
        };

        let backend = Self {
            name: config.name.clone(),
            client: Arc::new(RwLock::new(client)),
            auth_config: config.auth.clone(),
            allowed_paths: config.allowed_paths.clone(),
            last_reauth: Mutex::new(None),
        };

        if let Some(lease) = renewal {
            backend.spawn_renewal_task(lease);
        }

        info!(address = %config.address, name = %config.name, "Vault backend initialised");
        Ok(backend)
    }

    fn spawn_renewal_task(&self, initial_lease: Option<Duration>) {
        let client = Arc::downgrade(&self.client);
        let auth = self.auth_config.clone();

        tokio::spawn(async move {
            let mut lease = initial_lease;
            loop {
                tokio::time::sleep(renewal_interval(lease)).await;

                let Some(client) = client.upgrade() else {
                    debug!("Vault backend dropped; stopping renewal task");
                    break;
                };
                match renew_or_login(&client, &auth).await {
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

    fn assert_path_allowed(&self, path: String) -> Result<(), SecretError> {
        if path_allowed(&self.allowed_paths, &path) {
            Ok(())
        } else {
            Err(SecretError::PathNotAllowed {
                backend: self.name.clone(),
                path,
            })
        }
    }

    async fn read_kv(&self, reference: &SecretRef) -> Result<SecretDataMap, ClientError> {
        let client = self.client.read().await;
        vaultrs::kv2::read::<SecretDataMap>(&*client, &reference.mount, &reference.path).await
    }

    /// Re-logs in after a denied read, at most once per [`REAUTH_MIN_INTERVAL`].
    /// Returns `false` when the window has not elapsed.
    async fn reauthenticate(&self) -> Result<bool, SecretError> {
        // A static token can't be replaced by logging in again.
        if matches!(self.auth_config, VaultAuthConfig::Token(_)) {
            return Ok(false);
        }
        {
            let mut last = self.last_reauth.lock().await;
            if last.is_some_and(|at| at.elapsed() < REAUTH_MIN_INTERVAL) {
                return Ok(false);
            }
            *last = Some(Instant::now());
        }
        warn!("Vault request was denied, re-authenticating");
        let mut client = self.client.write().await;
        authenticate(&mut client, &self.auth_config).await?;
        Ok(true)
    }

    /// Signs `public_key` into an OpenSSH user certificate for `principal`
    /// with the SSH secrets engine at `mount`, returned in OpenSSH wire format.
    pub async fn sign_ssh_key(
        &self,
        mount: &str,
        role: &str,
        public_key: &str,
        principal: &str,
        key_id: &str,
    ) -> Result<String, SecretError> {
        validate_path_segment(mount)?;
        validate_path_segment(role)?;
        self.assert_path_allowed(format!("{mount}/sign/{role}"))?;
        // Vault reads `valid_principals` as a comma-separated list, so a comma
        // would widen the certificate to accounts nobody named.
        if principal.is_empty()
            || principal.contains(',')
            || principal.chars().any(char::is_control)
        {
            return Err(SecretError::InvalidSshSigningRequest(format!(
                "principal {principal:?}"
            )));
        }
        if key_id.len() > MAX_SSH_KEY_ID || key_id.chars().any(char::is_control) {
            return Err(SecretError::InvalidSshSigningRequest(format!(
                "key ID {key_id:?}"
            )));
        }

        let result = match self
            .sign_once(mount, role, public_key, principal, key_id)
            .await
        {
            Err(ClientError::APIError { code: 403, .. }) if self.reauthenticate().await? => {
                self.sign_once(mount, role, public_key, principal, key_id)
                    .await
            }
            other => other,
        };
        result.map(|r| r.signed_key).map_err(sign_error)
    }

    async fn sign_once(
        &self,
        mount: &str,
        role: &str,
        public_key: &str,
        principal: &str,
        key_id: &str,
    ) -> Result<SignSSHKeyResponse, ClientError> {
        let mut opts = SignSSHKeyRequest::builder();
        opts.cert_type("user")
            .valid_principals(principal)
            .key_id(key_id)
            .ttl(CERTIFICATE_TTL);
        let client = self.client.read().await;
        vaultrs::ssh::ca::sign(&*client, mount, role, public_key, Some(&mut opts)).await
    }

    /// A token lookup proves the server is reachable and unsealed and that
    /// the credentials this backend resolves with are still accepted, which
    /// the unauthenticated `sys/health` cannot.
    pub async fn health(&self) -> Result<(), SecretError> {
        let client = self.client.read().await;
        vaultrs::token::lookup_self(&*client)
            .await
            .map(|_| ())
            .map_err(|e| SecretError::Backend(format!("token check: {e}")))
    }
}

#[async_trait]
impl SecretResolver for VaultBackend {
    async fn resolve(&self, reference: &SecretRef) -> Result<Secret<String>, SecretError> {
        self.assert_path_allowed(reference.kv_path())?;

        let data = match self.read_kv(reference).await {
            Ok(data) => data,
            Err(ClientError::APIError { code: 403, .. }) if self.reauthenticate().await? => self
                .read_kv(reference)
                .await
                .map_err(|e| read_error(reference, e))?,
            Err(e) => return Err(read_error(reference, e)),
        };

        data.get(&reference.field)
            .map(|v| Secret::new(value_to_string(v)))
            .ok_or_else(|| SecretError::NotFound {
                path: reference.kv_path(),
            })
    }
}

/// Prefixes match whole path segments: `secret/app` covers `secret/app/db`
/// but not `secret/apple`.
fn path_allowed(allowed: &[String], path: &str) -> bool {
    allowed.is_empty()
        || allowed.iter().any(|prefix| {
            let prefix = prefix.trim_end_matches('/');
            path == prefix
                || path
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
}

fn read_error(reference: &SecretRef, error: ClientError) -> SecretError {
    match error {
        ClientError::APIError { code: 404, .. } => SecretError::NotFound {
            path: reference.kv_path(),
        },
        other => SecretError::Backend(format!("KV v2 read {}: {other}", reference.kv_path())),
    }
}

/// A mount or role is interpolated into the request path, so it has to be a
/// single segment.
fn validate_path_segment(name: &str) -> Result<(), SecretError> {
    if !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        Ok(())
    } else {
        Err(SecretError::InvalidSshSigningRequest(format!(
            "mount or role {name:?}"
        )))
    }
}

fn sign_error(error: ClientError) -> SecretError {
    match error {
        ClientError::APIError { code, errors } => SecretError::SshSigning {
            status: code,
            message: errors.join("; "),
        },
        other => SecretError::Backend(format!("SSH sign: {other}")),
    }
}

fn value_to_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn renewal_interval(lease: Option<Duration>) -> Duration {
    const MIN: Duration = Duration::from_secs(5);
    const FALLBACK: Duration = Duration::from_secs(60);
    match lease {
        Some(l) if !l.is_zero() => l.mul_f64(0.75).max(MIN),
        _ => FALLBACK,
    }
}

/// The TTL to renew a static token at, or `None` when it can't be renewed (a
/// root or non-renewable token) or can't be inspected right now.
async fn renewable_token_ttl(client: &VaultClient, name: &str) -> Option<Option<Duration>> {
    match vaultrs::token::lookup_self(client).await {
        Ok(token) if token.renewable && token.ttl > 0 => Some(Some(Duration::from_secs(token.ttl))),
        Ok(_) => {
            debug!(name, "Vault token is not renewable; skipping renewal");
            None
        }
        Err(e) => {
            warn!(name, error = %e, "Could not inspect the Vault token; it will not be renewed");
            None
        }
    }
}

/// Extends the current token's lease; a token that can't be renewed is
/// replaced by logging in again, which static tokens can't do.
async fn renew_or_login(
    client: &RwLock<VaultClient>,
    auth: &VaultAuthConfig,
) -> Result<Option<Duration>, SecretError> {
    let renewed = {
        let client = client.read().await;
        vaultrs::token::renew_self(&*client, None).await
    };
    match renewed {
        Ok(info) => Ok(Some(Duration::from_secs(info.lease_duration))),
        Err(e) if matches!(auth, VaultAuthConfig::Token(_)) => {
            Err(SecretError::Backend(format!("token renewal: {e}")))
        }
        Err(e) => {
            debug!("Vault token renewal failed ({e}); logging in again");
            let mut client = client.write().await;
            authenticate(&mut client, auth).await
        }
    }
}

fn reveal(stored: &StoredSecret) -> Result<Secret<String>, SecretError> {
    stored
        .reveal()
        .map_err(|e| SecretError::Backend(format!("decrypt stored credential: {e}")))
}

// vaultrs panics on a token that is not a valid header value.
fn use_token(client: &mut VaultClient, token: &str) -> Result<(), SecretError> {
    let token = token.trim();
    if !token.chars().all(|c| c.is_ascii_graphic()) {
        return Err(SecretError::Backend(
            "the Vault token contains characters a header can't carry".into(),
        ));
    }
    client.set_token(token);
    Ok(())
}

async fn authenticate(
    client: &mut VaultClient,
    auth: &VaultAuthConfig,
) -> Result<Option<Duration>, SecretError> {
    match auth {
        VaultAuthConfig::Token(VaultTokenAuth { token }) => {
            use_token(client, reveal(token)?.expose_secret())?;
            Ok(None)
        }
        VaultAuthConfig::AppRole(VaultAppRoleAuth {
            role_id,
            secret_id,
            mount,
        }) => {
            let info = vaultrs::auth::approle::login(
                client,
                mount.as_deref().unwrap_or("approle"),
                role_id.trim(),
                reveal(secret_id)?.expose_secret().trim(),
            )
            .await
            .map_err(|e| SecretError::Backend(format!("AppRole login: {e}")))?;

            use_token(client, &info.client_token)?;
            Ok(Some(Duration::from_secs(info.lease_duration)))
        }
        VaultAuthConfig::Kubernetes(VaultKubernetesAuth { role, mount }) => {
            let jwt = tokio::fs::read_to_string(KUBERNETES_JWT_PATH)
                .await
                .map_err(|e| {
                    SecretError::Backend(format!("read JWT from {KUBERNETES_JWT_PATH}: {e}"))
                })?;

            let info = vaultrs::auth::kubernetes::login(
                client,
                mount.as_deref().unwrap_or("kubernetes"),
                role,
                jwt.trim(),
            )
            .await
            .map_err(|e| SecretError::Backend(format!("Kubernetes login: {e}")))?;

            use_token(client, &info.client_token)?;
            Ok(Some(Duration::from_secs(info.lease_duration)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(kv_path: &str) -> SecretRef {
        format!("secret://b/{kv_path}#f").parse().unwrap()
    }

    #[test]
    fn renewal_interval_renews_before_expiry() {
        assert_eq!(
            renewal_interval(Some(Duration::from_secs(3600))),
            Duration::from_secs(2700)
        );
        assert!(renewal_interval(Some(Duration::from_secs(2))) < Duration::from_secs(60));
        assert_eq!(renewal_interval(None), Duration::from_secs(60));
        assert_eq!(
            renewal_interval(Some(Duration::ZERO)),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn allowed_paths_match_whole_segments() {
        let allowed = vec!["secret/app".to_string(), "kv/team/".to_string()];
        assert!(path_allowed(&allowed, "secret/app"));
        assert!(path_allowed(&allowed, "secret/app/db"));
        assert!(path_allowed(&allowed, "kv/team/x"));
        assert!(!path_allowed(&allowed, "secret/apple"));
        assert!(!path_allowed(&allowed, "secret/app-admin/db"));
        assert!(!path_allowed(&allowed, "kv/teams/x"));
        assert!(path_allowed(&[], "anything/at/all"));
    }

    #[test]
    fn read_errors_map_404_to_not_found() {
        let not_found = read_error(
            &reference("secret/app"),
            ClientError::APIError {
                code: 404,
                errors: vec![],
            },
        );
        assert!(matches!(not_found, SecretError::NotFound { path } if path == "secret/app"));
        let other = read_error(
            &reference("secret/app"),
            ClientError::APIError {
                code: 500,
                errors: vec![],
            },
        );
        assert!(matches!(other, SecretError::Backend(_)));
    }

    #[test]
    fn sign_errors_keep_the_status_and_message() {
        let refused = sign_error(ClientError::APIError {
            code: 400,
            errors: vec!["root is not a valid value for valid_principals".into()],
        });
        assert!(matches!(
            refused,
            SecretError::SshSigning { status: 400, ref message } if message.contains("valid_principals")
        ));
        assert!(matches!(
            sign_error(ClientError::APIError {
                code: 500,
                errors: vec![],
            }),
            SecretError::SshSigning { status: 500, .. }
        ));
    }

    #[tokio::test]
    async fn static_token_is_trimmed_and_must_fit_a_header() {
        let mut builder = VaultClientSettingsBuilder::default();
        builder.address("https://vault.invalid").token("");
        let mut client = VaultClient::new(builder.build().unwrap()).unwrap();
        let token = |value: &str| {
            VaultAuthConfig::Token(VaultTokenAuth {
                token: StoredSecret::new(Secret::new(value.into())),
            })
        };

        let pasted = authenticate(&mut client, &token("hvs.abc\n")).await;
        assert!(pasted.is_ok());
        assert_eq!(client.settings.token, "hvs.abc");
        let broken = authenticate(&mut client, &token("hvs.a\nbc")).await;
        assert!(broken.is_err());
    }

    #[test]
    fn mounts_and_roles_are_single_path_segments() {
        assert!(validate_path_segment("ssh-client_signer1").is_ok());
        for bad in ["", "a/b", "../x", "a b"] {
            assert!(validate_path_segment(bad).is_err(), "{bad:?}");
        }
    }
}
