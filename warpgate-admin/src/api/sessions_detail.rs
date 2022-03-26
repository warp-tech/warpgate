use crate::helpers::ApiResult;
use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_common::{SessionSnapshot, State};
use warpgate_db_entities::{Recording, Session};

pub struct Api;

#[allow(clippy::large_enum_variant)]
#[derive(ApiResponse)]
enum GetSessionResponse {
    #[oai(status = 200)]
    Ok(Json<SessionSnapshot>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum GetSessionRecordingsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<Recording::Model>>),
}

#[derive(ApiResponse)]
enum CloseSessionResponse {
    #[oai(status = 201)]
    Ok,
    #[oai(status = 404)]
    NotFound,
}

#[OpenApi]
impl Api {
    #[oai(path = "/sessions/:id", method = "get", operation_id = "get_session")]
    async fn api_get_session(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
    ) -> ApiResult<GetSessionResponse> {
        let db = db.lock().await;

        let session = Session::Entity::find_by_id(id.0)
            .one(&*db)
            .await
            .map_err(poem::error::InternalServerError)?;

        match session {
            Some(session) => Ok(GetSessionResponse::Ok(Json(session.into()))),
            None => Ok(GetSessionResponse::NotFound),
        }
    }

    #[oai(
        path = "/sessions/:id/recordings",
        method = "get",
        operation_id = "get_session_recordings"
    )]
    async fn api_get_session_recordings(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
    ) -> ApiResult<GetSessionRecordingsResponse> {
        let db = db.lock().await;
        let recordings: Vec<Recording::Model> = Recording::Entity::find()
            .order_by_desc(Recording::Column::Started)
            .filter(Recording::Column::SessionId.eq(id.0))
            .all(&*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        Ok(GetSessionRecordingsResponse::Ok(Json(recordings)))
    }

    #[oai(
        path = "/sessions/:id/close",
        method = "post",
        operation_id = "close_session"
    )]
    async fn api_close_session(
        &self,
        state: Data<&Arc<Mutex<State>>>,
        id: Path<Uuid>,
    ) -> CloseSessionResponse {
        let state = state.lock().await;

        if let Some(s) = state.sessions.get(&id) {
            let mut session = s.lock().await;
            session.handle.close();
            CloseSessionResponse::Ok
        } else {
            CloseSessionResponse::NotFound
        }
    }
}
