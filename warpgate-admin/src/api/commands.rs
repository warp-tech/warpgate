use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::prelude::Expr;
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_db_entities::Command;

use super::AdminContext;
use super::pagination::PaginatedResponse;
use crate::api::common::case_insensitive_search_expr;

pub struct Api;

#[derive(ApiResponse)]
enum GetCommandsResponse {
    #[oai(status = 200)]
    Ok(Json<PaginatedResponse<CommandEntry>>),
}

#[derive(Object)]
struct GetCommandsRequest {
    search: Option<String>,
    /// Keyset cursor: only rows with `timestamp` strictly before this are returned.
    before: Option<OffsetDateTime>,
    limit: Option<u64>,
}

#[derive(Object)]
pub struct CommandEntry {
    id: Uuid,
    timestamp: OffsetDateTime,
    username: Option<String>,
    command: String,
    user_session_id: Uuid,
    target_session_id: Option<Uuid>,
}

impl From<Command::Model> for CommandEntry {
    fn from(model: Command::Model) -> Self {
        Self {
            id: model.id,
            timestamp: model.timestamp,
            username: model.username,
            command: model.command,
            user_session_id: model.user_session_id,
            target_session_id: model.target_session_id,
        }
    }
}

#[OpenApi]
impl Api {
    #[oai(path = "/commands", method = "post", operation_id = "get_commands")]
    async fn api_get_commands(
        &self,
        admin: AdminContext,
        body: Json<GetCommandsRequest>,
    ) -> Result<GetCommandsResponse, WarpgateError> {
        admin.require(AdminPermission::SessionsView)?;

        let db = &admin.services().db;
        let mut q = Command::Entity::find().order_by_desc(Command::Column::Timestamp);

        if let Some(before) = body.before {
            q = q.filter(Command::Column::Timestamp.lt(before));
        }
        if let Some(ref search) = body.search
            && !search.is_empty()
        {
            q = q.filter(case_insensitive_search_expr(
                search,
                [
                    Expr::col(Command::Column::Command).into(),
                    Expr::col(Command::Column::Username).into(),
                ],
            ));
        }

        let total = q.clone().count(db).await.map_err(WarpgateError::from)?;
        let commands = q
            .limit(body.limit.unwrap_or(100).clamp(1, 500))
            .all(db)
            .await
            .map_err(WarpgateError::from)?;

        Ok(GetCommandsResponse::Ok(Json(
            PaginatedResponse::from_parts(
                commands.into_iter().map(CommandEntry::from).collect(),
                0,
                total,
            ),
        )))
    }
}
