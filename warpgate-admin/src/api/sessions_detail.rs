use poem::http::StatusCode;
use poem::session::Session;
use poem_openapi::param::{Path, Query};
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use uuid::Uuid;
use warpgate_common::{AdminPermission, UserSessionId, WarpgateError};
use warpgate_core::UserSessionSnapshot;
use warpgate_db_entities::{Recording, TargetSession, UserSession};

use super::sessions_list::user_session_snapshots;
use super::{AdminContext, ClusterOrAdminContext};
use crate::api::cluster_proxy::fan_out_to_peers;

pub struct Api;

#[allow(clippy::large_enum_variant)]
#[derive(ApiResponse)]
enum GetSessionResponse {
    #[oai(status = 200)]
    Ok(Json<UserSessionSnapshot>),
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
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<GetSessionResponse, WarpgateError> {
        admin.require(AdminPermission::SessionsView)?;

        let db = &admin.services().db;

        let Some(session) = UserSession::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(GetSessionResponse::NotFound);
        };
        let Some(snapshot) = user_session_snapshots(db, vec![session])
            .await?
            .into_iter()
            .next()
        else {
            return Ok(GetSessionResponse::NotFound);
        };
        Ok(GetSessionResponse::Ok(Json(snapshot)))
    }

    #[oai(
        path = "/sessions/:id/recordings",
        method = "get",
        operation_id = "get_session_recordings"
    )]
    async fn api_get_session_recordings(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<GetSessionRecordingsResponse, WarpgateError> {
        admin.require(AdminPermission::RecordingsView)?;

        let db = &admin.services().db;
        let target_ids = TargetSession::Entity::find()
            .select_only()
            .column(TargetSession::Column::Id)
            .filter(TargetSession::Column::UserSessionId.eq(id.0))
            .into_tuple::<Uuid>()
            .all(db)
            .await?;
        let recordings = if target_ids.is_empty() {
            vec![]
        } else {
            Recording::Entity::find()
                .order_by_desc(Recording::Column::Started)
                .filter(Recording::Column::SessionId.is_in(target_ids))
                .all(db)
                .await?
        };
        Ok(GetSessionRecordingsResponse::Ok(Json(recordings)))
    }

    #[oai(
        path = "/sessions/:id/close",
        method = "post",
        operation_id = "close_session"
    )]
    async fn api_close_session(
        &self,
        admin: ClusterOrAdminContext,
        id: Path<Uuid>,
        req: &poem::Request,
        browser_session: &Session,
        /// Close only connections owned by this node.
        local_only: Query<Option<bool>>,
    ) -> poem::Result<CloseSessionResponse> {
        admin.require(AdminPermission::SessionsTerminate)?;

        let session = UserSession::Entity::find_by_id(id.0)
            .one(&admin.services().db)
            .await
            .map_err(WarpgateError::from)?;
        let Some(session) = session else {
            return Ok(CloseSessionResponse::NotFound);
        };
        if session.ended.is_some() {
            return Ok(CloseSessionResponse::NotFound);
        }
        let user_state = {
            let state = admin.services().state.lock().await;
            state.user_sessions.get(&UserSessionId(id.0)).cloned()
        };
        if let Some(user_state) = user_state {
            user_state.lock().await.handle.close();
        }

        if browser_session.get::<Uuid>("session_id") == Some(id.0) {
            browser_session.purge();
        }

        if !local_only.unwrap_or(false) {
            close_on_peers(&admin, req).await;
            warpgate_core::db::mark_user_session_and_targets_ended(&admin.services().db, UserSessionId(id.0))
                .await
                .map_err(poem::error::InternalServerError)?;
        }

        Ok(CloseSessionResponse::Ok)
    }
}

async fn close_on_peers(
    ctx: &warpgate_common_http::AuthenticatedRequestContext,
    req: &poem::Request,
) {
    let path = format!("{}?local_only=true", req.original_uri().path());
    for (hostname, response) in fan_out_to_peers(ctx, req, &path).await {
        if response.status() != StatusCode::CREATED {
            tracing::warn!(node = %hostname, status = %response.status(), "Failed to close a user session on a cluster node");
        }
    }
}
