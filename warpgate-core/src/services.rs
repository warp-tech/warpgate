use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use sea_orm::DatabaseConnection;
use tokio::sync::Mutex;
use tracing::{info, warn};
use warpgate_common::WarpgateConfig;

use crate::db::{connect_to_db, populate_db};
use crate::login_protection::LoginProtectionService;
use crate::rate_limiting::RateLimiterRegistry;
use crate::recordings::SessionRecordings;
use crate::{AuthStateStore, ConfigProviderEnum, DatabaseConfigProvider, State};

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
}

impl Services {
    pub async fn new(mut config: WarpgateConfig, admin_token: Option<String>) -> Result<Self> {
        let mut db = connect_to_db(&config).await?;
        populate_db(&mut db, &mut config).await?;
        let db = Arc::new(Mutex::new(db));

        let recordings = SessionRecordings::new(db.clone(), &config)?;
        let recordings = Arc::new(Mutex::new(recordings));

        let config = Arc::new(Mutex::new(config));

        let config_provider = Arc::new(Mutex::new(DatabaseConfigProvider::new(&db).await.into()));

        let auth_state_store = Arc::new(Mutex::new(AuthStateStore::new(config_provider.clone())));

        tokio::spawn({
            let auth_state_store = auth_state_store.clone();
            async move {
                loop {
                    auth_state_store.lock().await.vacuum().await;
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
            }
        });

        let mut rate_limiter_registry = RateLimiterRegistry::new(db.clone());
        rate_limiter_registry.refresh().await?;
        let rate_limiter_registry = Arc::new(Mutex::new(rate_limiter_registry));

        // Initialize login protection service
        let login_protection_config = config.lock().await.store.login_protection.clone();
        let login_protection =
            Arc::new(LoginProtectionService::new(login_protection_config, db.clone()).await?);

        // Background cleanup task for login protection (runs every hour)
        if login_protection.is_enabled() {
            let login_protection_clone = login_protection.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(3600));
                loop {
                    interval.tick().await;
                    match login_protection_clone.cleanup_expired().await {
                        Ok(stats) => {
                            if stats.expired_blocks_removed > 0
                                || stats.expired_lockouts_removed > 0
                                || stats.old_attempts_removed > 0
                            {
                                info!(
                                    expired_blocks = stats.expired_blocks_removed,
                                    expired_lockouts = stats.expired_lockouts_removed,
                                    old_attempts = stats.old_attempts_removed,
                                    "Login protection cleanup completed"
                                );
                            }
                        }
                        Err(e) => {
                            warn!("Login protection cleanup failed: {}", e);
                        }
                    }
                }
            });
        }

        Ok(Self {
            db: db.clone(),
            recordings,
            config: config.clone(),
            state: State::new(&db, &rate_limiter_registry)?,
            rate_limiter_registry,
            config_provider,
            auth_state_store,
            admin_token: Arc::new(Mutex::new(admin_token)),
            login_protection,
        })
    }
}
