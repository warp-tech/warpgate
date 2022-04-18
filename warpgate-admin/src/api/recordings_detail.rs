use crate::helpers::{authorized, ApiResult};
use bytes::Bytes;
use poem::error::{InternalServerError, NotFoundError};
use poem::handler;
use poem::session::Session;
use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{DatabaseConnection, EntityTrait};
use serde::Serialize;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_common::recordings::{SessionRecordings, TerminalRecordingItem};
use warpgate_db_entities::Recording::{self, RecordingKind};

pub struct Api;

#[derive(ApiResponse)]
enum GetRecordingResponse {
    #[oai(status = 200)]
    Ok(Json<Recording::Model>),
    #[oai(status = 404)]
    NotFound,
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/recordings/:id",
        method = "get",
        operation_id = "get_recording"
    )]
    async fn api_get_recording(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        session: &Session,
    ) -> ApiResult<GetRecordingResponse> {
        authorized(session, || async move {
            let db = db.lock().await;

            let recording = Recording::Entity::find_by_id(id.0)
                .one(&*db)
                .await
                .map_err(InternalServerError)?;

            match recording {
                Some(recording) => Ok(GetRecordingResponse::Ok(Json(recording))),
                None => Ok(GetRecordingResponse::NotFound),
            }
        })
        .await
    }
}

#[handler]
pub async fn api_get_recording_cast(
    db: Data<&Arc<Mutex<DatabaseConnection>>>,
    recordings: Data<&Arc<Mutex<SessionRecordings>>>,
    id: poem::web::Path<Uuid>,
    session: &Session,
) -> ApiResult<String> {
    authorized(session, || async move {
        let db = db.lock().await;

        let recording = Recording::Entity::find_by_id(id.0)
            .one(&*db)
            .await
            .map_err(InternalServerError)?;

        let Some(recording) = recording else {
            return Err(NotFoundError.into())
        };

        if recording.kind != RecordingKind::Terminal {
            return Err(NotFoundError.into());
        }

        let path = {
            recordings
                .lock()
                .await
                .path_for(&recording.session_id, &recording.name)
        };

        let mut response = vec![]; //String::new();

        let mut last_size = (80, 25);
        let file = File::open(&path).await.map_err(InternalServerError)?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        while let Some(line) = lines.next_line().await.map_err(InternalServerError)? {
            let entry: TerminalRecordingItem =
                serde_json::from_str(&line[..]).map_err(InternalServerError)?;
            match entry {
                TerminalRecordingItem::Data { time, data } => {
                    response.push(
                        serde_json::to_string(&Cast::Output(
                            time,
                            "o".to_string(),
                            String::from_utf8_lossy(&data[..]).to_string(),
                        ))
                        .map_err(InternalServerError)?,
                    );
                }
                TerminalRecordingItem::PtyResize { time, cols, rows } => {
                    last_size = (cols, rows);
                    response.push(
                        serde_json::to_string(&Cast::Header {
                            time,
                            version: 2,
                            width: cols,
                            height: rows,
                            title: recording.name.clone(),
                        })
                        .map_err(InternalServerError)?,
                    );
                }
            }
        }

        response.insert(
            0,
            serde_json::to_string(&Cast::Header {
                time: 0.0,
                version: 2,
                width: last_size.0,
                height: last_size.1,
                title: recording.name,
            })
            .map_err(InternalServerError)?,
        );

        Ok(response.join("\n"))
    })
    .await
}

#[handler]
pub async fn api_get_recording_tcpdump(
    db: Data<&Arc<Mutex<DatabaseConnection>>>,
    recordings: Data<&Arc<Mutex<SessionRecordings>>>,
    id: poem::web::Path<Uuid>,
    session: &Session,
) -> ApiResult<Bytes> {
    authorized(session, || async move {
        let db = db.lock().await;

        let recording = Recording::Entity::find_by_id(id.0)
            .one(&*db)
            .await
            .map_err(poem::error::InternalServerError)?;

        let Some(recording) = recording else {
            return Err(NotFoundError.into())
        };

        if recording.kind != RecordingKind::Traffic {
            return Err(NotFoundError.into());
        }

        let path = {
            recordings
                .lock()
                .await
                .path_for(&recording.session_id, &recording.name)
        };

        let content = std::fs::read(path).map_err(InternalServerError)?;

        Ok(Bytes::from(content))
    })
    .await
}

#[derive(Serialize)]
#[serde(untagged)]
enum Cast {
    Header {
        time: f32,
        version: u32,
        width: u32,
        height: u32,
        title: String,
    },
    Output(f32, String, String),
}

// #[handler]
// pub async fn api_get_recording_stream(
//     ws: WebSocket,
//     db: Data<&Arc<Mutex<DatabaseConnection>>>,
//     state: Data<&Arc<Mutex<State>>>,
//     id: poem::web::Path<Uuid>,
// ) -> impl IntoResponse {
//     ws.on_upgrade(|socket| async move {

//     })
// }
