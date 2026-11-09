use poem::session::Session;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use uuid::Uuid;
use warpgate_common::{AdminPermission, UserSessionId, WarpgateError};
use warpgate_core::{SessionsFilter, UserSessionSnapshot};
use warpgate_db_entities::{HttpSession, Recording, TargetSession, UserSession};

use super::AdminContext;
use super::sessions_list::user_session_snapshots;

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
        id: Path<UserSessionId>,
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
        id: Path<UserSessionId>,
    ) -> Result<GetSessionRecordingsResponse, WarpgateError> {
        admin.require(AdminPermission::RecordingsView)?;

        let db = &admin.services().db;
        let target_session_ids = TargetSession::Entity::find()
            .select_only()
            .column(TargetSession::Column::Id)
            .filter(TargetSession::Column::UserSessionId.eq(id.0))
            .into_tuple::<Uuid>()
            .all(db)
            .await?;
        let recordings = if target_session_ids.is_empty() {
            vec![]
        } else {
            Recording::Entity::find()
                .order_by_desc(Recording::Column::Started)
                .filter(Recording::Column::SessionId.is_in(target_session_ids))
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
        admin: AdminContext,
        id: Path<UserSessionId>,
        browser_session: &Session,
    ) -> poem::Result<CloseSessionResponse> {
        admin.require(AdminPermission::SessionsTerminate)?;

        let session = UserSession::Entity::find_by_id(id.0)
            .one(&admin.services().db)
            .await
            .map_err(WarpgateError::from)?;
        if session.is_none_or(|session| session.ended.is_some()) {
            return Ok(CloseSessionResponse::NotFound);
        }

        admin
            .services()
            .close_sessions(SessionsFilter::Sessions { ids: vec![id.0] })
            .await
            .map_err(poem::error::InternalServerError)?;

        if browser_session.get::<UserSessionId>(HttpSession::SESSION_ID_DATA_KEY) == Some(id.0) {
            browser_session.purge();
        }

        Ok(CloseSessionResponse::Ok)
    }
}
