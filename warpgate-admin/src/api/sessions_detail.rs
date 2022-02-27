use crate::helpers::ApiResult;
use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::EntityTrait;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_common::{SessionSnapshot, State};

pub struct Api;

#[derive(ApiResponse)]
enum GetSessionResponse {
    #[oai(status = 200)]
    Ok(Json<SessionSnapshot>),
    #[oai(status = 404)]
    NotFound,
}

#[OpenApi]
impl Api {
    #[oai(path = "/sessions/:id", method = "get", operation_id = "get_session")]
    async fn api_get_all_sessions(
        &self,
        state: Data<&Arc<Mutex<State>>>,
        id: Path<Uuid>,
    ) -> ApiResult<GetSessionResponse> {
        use warpgate_db_entities::Session;

        let state = state.lock().await;

        let session = Session::Entity::find_by_id(id.0)
            .one(&state.db)
            .await
            .map_err(poem::error::InternalServerError)?;

        match session {
            Some(session) => Ok(GetSessionResponse::Ok(Json(session.into()))),
            None => Ok(GetSessionResponse::NotFound),
        }
    }
}
