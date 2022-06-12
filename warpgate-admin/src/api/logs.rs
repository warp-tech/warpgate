use chrono::{DateTime, Utc};
use poem::web::Data;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_db_entities::LogEntry;

pub struct Api;

#[derive(ApiResponse)]
enum GetLogsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<LogEntry::Model>>),
}

#[derive(Object)]
struct GetLogsRequest {
    before: Option<DateTime<Utc>>,
    after: Option<DateTime<Utc>>,
    limit: Option<u64>,
    session_id: Option<Uuid>,
    username: Option<String>,
    search: Option<String>,
}

#[OpenApi]
impl Api {
    #[oai(path = "/logs", method = "post", operation_id = "get_logs")]
    async fn api_get_all_logs(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        body: Json<GetLogsRequest>,
    ) -> poem::Result<GetLogsResponse> {
        use warpgate_db_entities::LogEntry;

        let db = db.lock().await;
        let mut q = LogEntry::Entity::find()
            .order_by_desc(LogEntry::Column::Timestamp)
            .limit(body.limit.unwrap_or(100));

        if let Some(before) = body.before {
            q = q.filter(LogEntry::Column::Timestamp.lt(before));
        }
        if let Some(after) = body.after {
            q = q
                .filter(LogEntry::Column::Timestamp.gt(after))
                .order_by_asc(LogEntry::Column::Timestamp);
        }
        if let Some(ref session_id) = body.session_id {
            q = q.filter(LogEntry::Column::SessionId.eq(*session_id));
        }
        if let Some(ref username) = body.username {
            q = q.filter(LogEntry::Column::SessionId.eq(username.clone()));
        }
        if let Some(ref search) = body.search {
            q = q.filter(
                LogEntry::Column::Text
                    .contains(search)
                    .or(LogEntry::Column::Username.contains(search)),
            );
        }

        let logs = q
            .all(&*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        let logs = logs
            .into_iter()
            .map(Into::into)
            .collect::<Vec<LogEntry::Model>>();
        Ok(GetLogsResponse::Ok(Json(logs)))
    }
}
