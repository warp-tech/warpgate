use poem::web::Data;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use time::OffsetDateTime;
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
    before: Option<OffsetDateTime>,
    after: Option<OffsetDateTime>,
    limit: Option<u64>,
    session_id: Option<Uuid>,
    username: Option<String>,
    search: Option<String>,
    target: Option<String>,
    related_users: Option<Uuid>,
    related_access_roles: Option<Uuid>,
    related_admin_roles: Option<Uuid>,
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
        use warpgate_db_entities::LogEntry;

        require_admin_permission(&ctx, None).await?;

        let db = ctx.services().db.lock().await;
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
            q = q.filter(LogEntry::Column::Username.eq(username.clone()));
        }
        if let Some(ref target) = body.target {
            if !target.is_empty() {
                q = q.filter(LogEntry::Column::Target.eq(target.clone()));
            }
        }
        if let Some(ref related_user) = body.related_users {
            q = q.filter(LogEntry::Column::RelatedUsers.contains(format!("${related_user}$")));
        }
        if let Some(ref related_access_role) = body.related_access_roles {
            q = q.filter(
                LogEntry::Column::RelatedAccessRoles.contains(format!("${related_access_role}$")),
            );
        }
        if let Some(ref related_admin_role) = body.related_admin_roles {
            q = q.filter(
                LogEntry::Column::RelatedAdminRoles.contains(format!("${related_admin_role}$")),
            );
        }
        if let Some(ref search) = body.search {
            if !search.is_empty() {
                q = q.filter(
                    LogEntry::Column::Text
                        .contains(search)
                        .or(LogEntry::Column::Username.contains(search))
                        .or(LogEntry::Column::Values.contains(search)),
                );
            }
        }

        let logs = q.all(&*db).await?;
        Ok(GetLogsResponse::Ok(Json(logs)))
    }
}
