use anyhow::{Context, Result};
use sea_orm::{ActiveModelTrait, DatabaseConnection};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::*;
use uuid::Uuid;
use warpgate_db_entities::Recording::{self, RecordingKind};

use crate::SessionId;
mod terminal;
mod writer;
mod traffic;
pub use terminal::*;
pub use traffic::*;
use writer::RecordingWriter;

pub trait Recorder {
    fn kind() -> RecordingKind;
    fn new(writer: RecordingWriter) -> Self;
}

pub struct SessionRecordings {
    db: Arc<Mutex<DatabaseConnection>>,
    path: PathBuf,
}

impl SessionRecordings {
    pub fn new(db: Arc<Mutex<DatabaseConnection>>, path: String) -> Result<Self> {
        std::fs::create_dir_all(&path)?;
        Ok(Self {
            db,
            path: PathBuf::from(path),
        })
    }

    pub async fn start<T>(&self, id: &SessionId, name: String) -> Result<T>
    where
        T: Recorder,
    {
        let path = self.path_for(id, &name);
        tokio::fs::create_dir_all(&path.parent().unwrap()).await?;
        info!(%name, path=?path, "Recording session {}", id);

        let model = {
            use sea_orm::ActiveValue::Set;
            let values = Recording::ActiveModel {
                id: Set(Uuid::new_v4()),
                started: Set(chrono::Utc::now()),
                session_id: Set(id.clone()),
                name: Set(name),
                kind: Set(T::kind()),
                ..Default::default()
            };

            let db = self.db.lock().await;
            values
                .insert(&*db)
                .await
                .context("Error inserting recording")?
        };

        let writer = RecordingWriter::new(path, model, self.db.clone()).await?;
        Ok(T::new(writer))
    }

    pub fn path_for(&self, session_id: &SessionId, name: &dyn AsRef<std::path::Path>) -> PathBuf {
        self.path.join(session_id.to_string()).join(&name)
    }
}
