use std::sync::Arc;

use anyhow::Result;
use sea_orm::DatabaseConnection;
use tokio::sync::Mutex;

use crate::db::{connect_to_db, sanitize_db};
use crate::recordings::SessionRecordings;
use crate::{ConfigProvider, FileConfigProvider, State, WarpgateConfig};

#[derive(Clone)]
pub struct Services {
    pub db: Arc<Mutex<DatabaseConnection>>,
    pub recordings: Arc<Mutex<SessionRecordings>>,
    pub config: Arc<Mutex<WarpgateConfig>>,
    pub state: Arc<Mutex<State>>,
    pub config_provider: Arc<Mutex<dyn ConfigProvider + Send + 'static>>,
}

impl Services {
    pub async fn new(config: WarpgateConfig) -> Result<Self> {
        let mut db = connect_to_db(&config).await?;
        sanitize_db(&mut db).await?;
        let db = Arc::new(Mutex::new(db));

        let recordings = SessionRecordings::new(db.clone(), &config)?;
        let recordings = Arc::new(Mutex::new(recordings));

        let config = Arc::new(Mutex::new(config));
        let config_provider = Arc::new(Mutex::new(FileConfigProvider::new(&db, &config).await));

        Ok(Self {
            db: db.clone(),
            recordings,
            config: config.clone(),
            state: State::new(&db),
            config_provider,
        })
    }
}
