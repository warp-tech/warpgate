use crate::helpers::ApiResult;
use poem::error::InternalServerError;
use poem::handler;
use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{DatabaseConnection, EntityTrait};
use serde::Serialize;
use tokio::fs::File;
use tokio::io::{BufReader, AsyncBufReadExt};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_common::{State, Record};
use warpgate_db_entities::Recording;

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
    ) -> ApiResult<GetRecordingResponse> {
        let db = db.lock().await;

        let recording = Recording::Entity::find_by_id(id.0)
            .one(&*db)
            .await
            .map_err(poem::error::InternalServerError)?;

        match recording {
            Some(recording) => Ok(GetRecordingResponse::Ok(Json(recording.into()))),
            None => Ok(GetRecordingResponse::NotFound),
        }
    }
}

#[handler]
pub async fn api_get_recording_cast(
    db: Data<&Arc<Mutex<DatabaseConnection>>>,
    state: Data<&Arc<Mutex<State>>>,
    id: poem::web::Path<Uuid>,
) -> ApiResult<String> {
    let db = db.lock().await;

    let recording = Recording::Entity::find_by_id(id.0)
        .one(&*db)
        .await
        .map_err(poem::error::InternalServerError)?;

    let Some(recording) = recording else {
        return Err(poem::error::NotFound(std::io::Error::new(std::io::ErrorKind::NotFound, "Not found")));
    };

    let path = {
        state
            .lock()
            .await
            .recordings
            .lock()
            .await
            .path_for(&recording.session_id, &recording.name)
    };

    let mut response = String::new();
    response.push_str(
        &serde_json::to_string(&Cast::Header {
            version: 2,
            width: 80,
            height: 25,
            title: recording.name,
        })
        .map_err(InternalServerError)?,
    );
    response.push_str("\n");

    let file = File::open(&path).await.map_err(InternalServerError)?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    while let Some(line) = lines.next_line().await.map_err(InternalServerError)? {
        let entry: Record = serde_json::from_str(&line[..]).map_err(InternalServerError)?;
        response.push_str(
            &serde_json::to_string(&Cast::Output(
                entry.time,
                "o".to_string(),
                String::from_utf8_lossy(&entry.data[..]).to_string(),
            )).map_err(InternalServerError)?
        );
        response.push_str("\n");
    }
    Ok(response)
}

#[derive(Serialize)]
#[serde(untagged)]
enum Cast {
    Header {
        version: u32,
        width: u32,
        height: u32,
        title: String,
    },
    Output(
        f32,
        String,
        String
    ),
}
