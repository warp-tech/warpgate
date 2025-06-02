use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use sea_orm::DatabaseConnection;
use tokio::sync::Mutex;
use warpgate_common::WarpgateConfig;

use crate::db::{connect_to_db, populate_db};
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

        Ok(Self {
            db: db.clone(),
            recordings,
            config: config.clone(),
            state: State::new(&db),
            config_provider,
            auth_state_store,
            admin_token: Arc::new(Mutex::new(admin_token)),
        })
    }
}
