use crate::helpers::ApiResult;
use poem::web::Data;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{EntityTrait, QueryOrder};
use std::sync::Arc;
use tokio::sync::Mutex;
use warpgate_common::{SessionSnapshot, State};

pub struct Api;

#[derive(ApiResponse)]
enum GetSessionsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<SessionSnapshot>>),
}

#[derive(ApiResponse)]
enum CloseAllSessionsResponse {
    #[oai(status = 200)]
    Ok,
}

#[OpenApi]
impl Api {
    #[oai(path = "/sessions", method = "get", operation_id = "get_sessions")]
    async fn api_get_all_sessions(
        &self,
        state: Data<&Arc<Mutex<State>>>,
    ) -> ApiResult<GetSessionsResponse> {
        use warpgate_db_entities::Session;

        let state = state.lock().await;
        let sessions: Vec<Session::Model> = Session::Entity::find()
            .order_by_desc(Session::Column::Started)
            .all(&state.db)
            .await
            .map_err(poem::error::InternalServerError)?;
        let sessions = sessions
            .into_iter()
            .map(|s| s.into())
            .collect::<Vec<SessionSnapshot>>();
        Ok(GetSessionsResponse::Ok(Json(sessions)))
    }

    #[oai(
        path = "/sessions",
        method = "delete",
        operation_id = "close_all_sessions"
    )]
    async fn api_close_all_sessions(
        &self,
        state: Data<&Arc<Mutex<State>>>,
    ) -> CloseAllSessionsResponse {
        let state = state.lock().await;

        for s in state.sessions.values() {
            let mut session = s.lock().await;
            session.handle.close();
        }

        CloseAllSessionsResponse::Ok
    }
}
