use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use sea_orm::DatabaseConnection;
use tokio::sync::Mutex;
use tracing::warn;
use uuid::Uuid;
use warpgate_common::auth::{AuthState, CredentialKind};
use warpgate_common::{GlobalParams, SessionId, WarpgateConfig, WarpgateError};

use crate::db::{connect_to_db_and_migrate, populate_db};
use crate::login_protection::LoginProtectionService;
use crate::rate_limiting::RateLimiterRegistry;
use crate::recordings::SessionRecordings;
use crate::{AuthStateStore, ConfigProviderEnum, DatabaseConfigProvider, State};

#[derive(Clone, Debug)]
pub struct EphemeralPublicKeyEntry {
    pub username: String,
    pub kind: russh::keys::Algorithm,
    pub public_key_bytes: bytes::Bytes,
    pub user_info: warpgate_common::auth::AuthStateUserInfo,
    pub expires_at: std::time::Instant,
}

#[derive(Clone)]
pub struct Services {
    pub db: Arc<Mutex<DatabaseConnection>>,
    pub recordings: Arc<Mutex<SessionRecordings>>,
    pub config: Arc<Mutex<WarpgateConfig>>,
    pub state: Arc<Mutex<State>>,
    pub config_provider: Arc<Mutex<ConfigProviderEnum>>,
    pub auth_state_store: Arc<Mutex<AuthStateStore>>,
    pub admin_token: Arc<Mutex<Option<String>>>,
    pub rate_limiter_registry: Arc<Mutex<RateLimiterRegistry>>,
    pub login_protection: Arc<LoginProtectionService>,
    pub global_params: Arc<GlobalParams>,
    pub ephemeral_public_keys: Arc<Mutex<Vec<EphemeralPublicKeyEntry>>>,
}

impl Services {
    pub async fn new(
        mut config: WarpgateConfig,
        admin_token: Option<String>,
        params: GlobalParams,
    ) -> Result<Self> {
        let db = connect_to_db_and_migrate(&config, &params).await?;
        populate_db(&db, &mut config).await?;
        let db = Arc::new(Mutex::new(db));

        let recordings = SessionRecordings::new(db.clone(), &config, &params)?;
        let recordings = Arc::new(Mutex::new(recordings));

        let config = Arc::new(Mutex::new(config));

        let config_provider = Arc::new(Mutex::new(DatabaseConfigProvider::new(&db).into()));

        let login_protection = Arc::new(LoginProtectionService::new(db.clone()).await?);

        let auth_state_store = Arc::new(Mutex::new(AuthStateStore::new()));
        let ephemeral_public_keys = Arc::new(Mutex::new(Vec::<EphemeralPublicKeyEntry>::new()));

        tokio::spawn({
            let auth_state_store = auth_state_store.clone();
            let ephemeral_public_keys = ephemeral_public_keys.clone();
            async move {
                loop {
                    auth_state_store.lock().await.vacuum();
                    ephemeral_public_keys
                        .lock()
                        .await
                        .retain(|e| e.expires_at > std::time::Instant::now());
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
            }
        });

        let rate_limiter_registry = RateLimiterRegistry::new(db.clone());
        rate_limiter_registry.refresh().await?;
        let rate_limiter_registry = Arc::new(Mutex::new(rate_limiter_registry));

        // Opt-in usage analytics reporter. Always spawned; it re-reads consent
        // from the DB on every run and reports nothing unless enabled.
        crate::analytics::start(db.clone());

        // Background cleanup task — always started; cleanup_expired() skips
        // work (and logs its own summary) when there is something to do, and
        // re-reads the enabled flag from the DB on each run.
        {
            let login_protection = login_protection.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60 * 60));
                loop {
                    interval.tick().await;
                    if let Err(e) = login_protection.cleanup_expired().await {
                        warn!("Login protection cleanup failed: {e}");
                    }
                }
            });
        }

        Ok(Self {
            db: db.clone(),
            recordings,
            config: config.clone(),
            state: State::new(&db, &rate_limiter_registry),
            rate_limiter_registry,
            config_provider,
            auth_state_store,
            admin_token: Arc::new(Mutex::new(admin_token)),
            login_protection,
            global_params: Arc::new(params),
            ephemeral_public_keys,
        })
    }

    pub async fn register_ephemeral_public_key(
        &self,
        username: &str,
        kind: russh::keys::Algorithm,
        public_key_bytes: bytes::Bytes,
        user_info: warpgate_common::auth::AuthStateUserInfo,
        ttl: Duration,
    ) {
        let mut cache = self.ephemeral_public_keys.lock().await;
        cache.retain(|e| {
            !(warpgate_common::helpers::username::username_eq_ci(&e.username, username)
                && e.kind == kind
                && e.public_key_bytes == public_key_bytes)
        });
        cache.push(EphemeralPublicKeyEntry {
            username: username.to_string(),
            kind: kind.clone(),
            public_key_bytes,
            user_info,
            expires_at: std::time::Instant::now() + ttl,
        });
        tracing::info!(
            username,
            ?kind,
            "Registered ephemeral public key after successful authentication"
        );
    }

    pub async fn is_ephemeral_public_key_authorized(
        &self,
        username: &str,
        kind: russh::keys::Algorithm,
        public_key_bytes: &[u8],
    ) -> Option<warpgate_common::auth::AuthStateUserInfo> {
        let mut cache = self.ephemeral_public_keys.lock().await;
        let now = std::time::Instant::now();
        cache.retain(|entry| entry.expires_at > now);
        for entry in cache.iter() {
            if warpgate_common::helpers::username::username_eq_ci(&entry.username, username)
                && entry.kind == kind
                && entry.public_key_bytes.as_ref() == public_key_bytes
            {
                return Some(entry.user_info.clone());
            }
        }
        None
    }

    /// Resolves the user/policy (without the store lock) and inserts a new
    /// [`AuthState`] under a brief store lock. This is the only sanctioned way
    /// to create an auth state, so the "no DB I/O while holding the store lock"
    /// invariant is enforced structurally rather than by convention.
    pub async fn create_auth_state(
        &self,
        session_id: Option<&SessionId>,
        username: &str,
        protocol: &str,
        supported_credential_types: &[CredentialKind],
        remote_ip: Option<IpAddr>,
        rate_limit_credential_type: Option<&str>,
    ) -> Result<(Uuid, Arc<Mutex<AuthState>>), WarpgateError> {
        let (user, policy) = AuthStateStore::resolve_user_and_policy(
            &self.config_provider,
            &self.login_protection,
            username,
            protocol,
            supported_credential_types,
            remote_ip,
            rate_limit_credential_type,
        )
        .await?;
        Ok(self
            .auth_state_store
            .lock()
            .await
            .create(session_id, &user, protocol, policy, remote_ip))
    }
}
