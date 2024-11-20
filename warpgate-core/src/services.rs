use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use sea_orm::DatabaseConnection;
use tokio::sync::Mutex;
use warpgate_common::{ConfigProviderKind, WarpgateConfig};

use crate::db::{connect_to_db, populate_db};
use crate::recordings::SessionRecordings;
use crate::{AuthStateStore, ConfigProvider, DatabaseConfigProvider, State};

type ConfigProviderArc = Arc<Mutex<dyn ConfigProvider + Send + 'static>>;

#[derive(Clone)]
pub struct Services {
    pub db: Arc<Mutex<DatabaseConnection>>,
    pub recordings: Arc<Mutex<SessionRecordings>>,
    pub config: Arc<Mutex<WarpgateConfig>>,
    pub state: Arc<Mutex<State>>,
    pub config_provider: ConfigProviderArc,
    pub auth_state_store: Arc<Mutex<AuthStateStore>>,
}

impl Services {
    pub async fn new(mut config: WarpgateConfig) -> Result<Self> {
        let mut db = connect_to_db(&config).await?;
        populate_db(&mut db, &mut config).await?;
        let db = Arc::new(Mutex::new(db));

        let recordings = SessionRecordings::new(db.clone(), &config)?;
        let recordings = Arc::new(Mutex::new(recordings));

        let provider = config.store.config_provider.clone();
        let config = Arc::new(Mutex::new(config));

        let config_provider = match provider {
            ConfigProviderKind::File => {
                anyhow::bail!("File based config provider in no longer supported");
            }
            ConfigProviderKind::Database => {
                Arc::new(Mutex::new(DatabaseConfigProvider::new(&db).await)) as ConfigProviderArc
            }
        };

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
        })
    }
}
