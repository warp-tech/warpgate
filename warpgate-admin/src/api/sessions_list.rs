use super::pagination::{PaginatedResponse, PaginationParams};
use poem::web::Data;
use poem_openapi::param::Query;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use std::sync::Arc;
use tokio::sync::Mutex;
use warpgate_common::{SessionSnapshot, State};

pub struct Api;

#[derive(ApiResponse)]
enum GetSessionsResponse {
    #[oai(status = 200)]
    Ok(Json<PaginatedResponse<SessionSnapshot>>),
}

#[derive(ApiResponse)]
enum CloseAllSessionsResponse {
    #[oai(status = 201)]
    Ok,
}

#[OpenApi]
impl Api {
    #[oai(path = "/sessions", method = "get", operation_id = "get_sessions")]
    async fn api_get_all_sessions(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        offset: Query<Option<u64>>,
        limit: Query<Option<u64>>,
        active_only: Query<Option<bool>>,
        logged_in_only: Query<Option<bool>>,
    ) -> poem::Result<GetSessionsResponse> {
        use warpgate_db_entities::Session;

        let db = db.lock().await;
        let mut q = Session::Entity::find().order_by_desc(Session::Column::Started);

        if active_only.unwrap_or(false) {
            q = q.filter(Session::Column::Ended.is_null());
        }
        if logged_in_only.unwrap_or(false) {
            q = q.filter(Session::Column::Username.is_not_null());
        }

        Ok(GetSessionsResponse::Ok(Json(
            PaginatedResponse::new(
                q,
                PaginationParams {
                    limit: *limit,
                    offset: *offset,
                },
                &*db,
                Into::into,
            )
            .await?,
        )))
    }

    #[oai(
        path = "/sessions",
        method = "delete",
        operation_id = "close_all_sessions"
    )]
    async fn api_close_all_sessions(
        &self,
        state: Data<&Arc<Mutex<State>>>,
    ) -> poem::Result<CloseAllSessionsResponse> {
        let state = state.lock().await;

        for s in state.sessions.values() {
            let mut session = s.lock().await;
            session.handle.close();
        }

        Ok(CloseAllSessionsResponse::Ok)
    }
}
