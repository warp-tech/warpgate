use chrono::{DateTime, Utc};
use poem::web::Data;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use uuid::Uuid;
use warpgate_common::WarpgateError;
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_db_entities::LogEntry;

use super::AnySecurityScheme;
use crate::api::common::require_admin_permission;

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
        ctx: Data<&AuthenticatedRequestContext>,
        body: Json<GetLogsRequest>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetLogsResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;

        use warpgate_db_entities::LogEntry;

        let db = ctx.services.db.lock().await;
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
                    .or(LogEntry::Column::Username.contains(search))
                    .or(LogEntry::Column::Values.contains(search)),
            );
        }

        let logs = q.all(&*db).await?;
        Ok(GetLogsResponse::Ok(Json(logs)))
    }
}
