use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use poem::session::Session;
use poem::web::websocket::{Message, WebSocket};
use poem::web::Data;
use poem::{handler, IntoResponse};
use poem_openapi::param::Query;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder};
use tokio::sync::Mutex;
use warpgate_core::{SessionSnapshot, State};

use super::pagination::{PaginatedResponse, PaginationParams};
use super::TokenSecurityScheme;

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
        _auth: TokenSecurityScheme,
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
        session: &Session,
        _auth: TokenSecurityScheme,
    ) -> poem::Result<CloseAllSessionsResponse> {
        let state = state.lock().await;

        for s in state.sessions.values() {
            let mut session = s.lock().await;
            session.handle.close();
        }

        session.purge();

        Ok(CloseAllSessionsResponse::Ok)
    }
}

#[handler]
pub async fn api_get_sessions_changes_stream(
    ws: WebSocket,
    state: Data<&Arc<Mutex<State>>>,
) -> impl IntoResponse {
    let mut receiver = state.lock().await.subscribe();

    ws.on_upgrade(|socket| async move {
        let (mut sink, _) = socket.split();

        while receiver.recv().await.is_ok() {
            sink.send(Message::Text("".to_string())).await?;
        }

        Ok::<(), anyhow::Error>(())
    })
}
