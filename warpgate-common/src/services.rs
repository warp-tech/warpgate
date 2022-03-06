use std::sync::Arc;

use anyhow::Result;
use sea_orm::DatabaseConnection;
use tokio::sync::Mutex;

use crate::{WarpgateConfig, State};
use crate::db::{connect_to_db, sanitize_db};
use crate::recordings::SessionRecordings;

#[derive(Clone)]
pub struct Services {
    pub db: Arc<Mutex<DatabaseConnection>>,
    pub recordings: Arc<Mutex<SessionRecordings>>,
    pub config: Arc<Mutex<WarpgateConfig>>,
    pub state: Arc<Mutex<State>>,
}

impl Services {
    pub async fn new(config: WarpgateConfig) -> Result<Self> {
        let mut db = connect_to_db(&config).await?;
        sanitize_db(&mut db).await?;
        let db = Arc::new(Mutex::new(db));

        let recordings = SessionRecordings::new(
            db.clone(),
            config.recordings_path.clone(),
        )?;
        let recordings = Arc::new(Mutex::new(recordings));

        Ok(Self {
            db: db.clone(),
            recordings,
            config: Arc::new(Mutex::new(config)),
            state: Arc::new(Mutex::new(State::new(&db))),
        })
    }
}
