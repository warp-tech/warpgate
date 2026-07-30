use poem::http::StatusCode;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use uuid::Uuid;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_core::SessionSnapshot;
use warpgate_core::db::mark_session_ended;
use warpgate_db_entities::{Node, Recording, Session};

use super::{AdminContext, ClusterOrAdminContext};
use crate::api::cluster_proxy::{ReparseForwardedResponse, proxy_or_serve, session_owner};

pub struct Api;

#[allow(clippy::large_enum_variant)]
#[derive(ApiResponse)]
enum GetSessionResponse {
    #[oai(status = 200)]
    Ok(Json<SessionSnapshot>),
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

impl ReparseForwardedResponse for CloseSessionResponse {
    fn reparse_forwarded_response(
        response: poem::Response,
    ) -> impl std::future::Future<Output = poem::Result<Self>> + Send {
        async move {
            match response.status() {
                StatusCode::CREATED => Ok(CloseSessionResponse::Ok),
                StatusCode::NOT_FOUND => Ok(CloseSessionResponse::NotFound),
                status => Err(poem::Error::from_string(
                    format!("Unexpected response from the owner node: {status}"),
                    StatusCode::BAD_GATEWAY,
                )),
            }
        }
    }
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

        let Some(session) = Session::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(GetSessionResponse::NotFound);
        };

        let mut snapshot: SessionSnapshot = session.into();
        snapshot.node_hostname = Node::Entity::find_by_id(snapshot.node_id)
            .one(db)
            .await?
            .map(|node| node.hostname);
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
        let recordings: Vec<Recording::Model> = Recording::Entity::find()
            .order_by_desc(Recording::Column::Started)
            .filter(Recording::Column::SessionId.eq(id.0))
            .all(db)
            .await?;
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
    ) -> poem::Result<CloseSessionResponse> {
        admin.require(AdminPermission::SessionsTerminate)?;

        let session = Session::Entity::find_by_id(id.0)
            .one(&admin.services().db)
            .await
            .map_err(WarpgateError::from)?;
        let Some(session) = session else {
            return Ok(CloseSessionResponse::NotFound);
        };
        if session.ended.is_some() {
            return Ok(CloseSessionResponse::NotFound);
        }
        let owner = match session_owner(&admin, &session).await {
            // The owner node is gone; nothing left to close.
            Err(WarpgateError::NodeGone(_)) => return Ok(CloseSessionResponse::NotFound),
            owner => owner?,
        };

        let state = admin.services().state.clone();
        let db = admin.services().db.clone();
        proxy_or_serve(&admin, req, owner, None::<&()>, async move || {
            let state = state.lock().await;
            if let Some(s) = state.sessions.get(&id) {
                s.lock().await.handle.close();
                drop(state);
                // a stuck event loop might never mark a session ended
                mark_session_ended(&db, id.0).await?;
                return Ok(CloseSessionResponse::Ok);
            }
            Ok(CloseSessionResponse::NotFound)
        })
        .await
    }
}
