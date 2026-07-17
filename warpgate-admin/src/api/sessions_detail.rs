use poem::http::StatusCode;
use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use uuid::Uuid;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::SessionSnapshot;
use warpgate_db_entities::{Node, Recording, Session};

use super::AnySecurityScheme;
use crate::api::cluster_proxy::{Owner, forward_http, session_owner};
use crate::api::common::{require_admin_permission, require_cluster_or_admin_permission};

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

#[OpenApi]
impl Api {
    #[oai(path = "/sessions/:id", method = "get", operation_id = "get_session")]
    async fn api_get_session(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetSessionResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::SessionsView)).await?;

        let db = &ctx.services().db;

        let Some(session) = Session::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(GetSessionResponse::NotFound);
        };

        let mut snapshot: SessionSnapshot = session.into();
        if let Some(node_id) = snapshot.node_id {
            snapshot.node_hostname = Node::Entity::find_by_id(node_id)
                .one(db)
                .await?
                .map(|node| node.hostname);
        }
        Ok(GetSessionResponse::Ok(Json(snapshot)))
    }

    #[oai(
        path = "/sessions/:id/recordings",
        method = "get",
        operation_id = "get_session_recordings"
    )]
    async fn api_get_session_recordings(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetSessionRecordingsResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::RecordingsView)).await?;

        let db = &ctx.services().db;
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
        ctx: Data<&AuthenticatedRequestContext>,
        id: Path<Uuid>,
        req: &poem::Request,
        _sec_scheme: AnySecurityScheme,
    ) -> poem::Result<CloseSessionResponse> {
        require_cluster_or_admin_permission(&ctx, AdminPermission::SessionsTerminate).await?;

        {
            let state = ctx.services().state.lock().await;
            if let Some(s) = state.sessions.get(&id) {
                s.lock().await.handle.close();
                return Ok(CloseSessionResponse::Ok);
            }
        }

        // No live handle here — the session may be owned by another node.
        let session = Session::Entity::find_by_id(id.0)
            .one(&ctx.services().db)
            .await
            .map_err(WarpgateError::from)?;
        let Some(session) = session else {
            return Ok(CloseSessionResponse::NotFound);
        };
        if session.ended.is_some() {
            return Ok(CloseSessionResponse::NotFound);
        }
        let owner = match session_owner(&ctx, &session).await {
            // The owner node is gone; nothing left to close.
            Err(WarpgateError::NodeGone(_)) => return Ok(CloseSessionResponse::NotFound),
            owner => owner?,
        };
        match owner {
            // Owned here but no live handle — already terminated.
            Owner::Local => Ok(CloseSessionResponse::NotFound),
            Owner::Remote(remote) => {
                let response =
                    forward_http(&ctx, req, remote, &ctx.services().cluster_token).await?;
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
}
