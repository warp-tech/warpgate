use futures::{SinkExt, StreamExt};
use poem::http::StatusCode;
use poem::session::Session;
use poem::web::Data;
use poem::web::websocket::{Message, WebSocket};
use poem::{IntoResponse, handler};
use poem_openapi::param::Query;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::prelude::Expr;
use sea_orm::sea_query::Func;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use tracing::warn;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::SessionSnapshot;
use warpgate_db_entities::Node;

use super::pagination::{PaginatedResponse, PaginationParams};
use super::{AdminContext, ClusterOrAdminContext};
use crate::api::cluster_proxy::forward_http_to;
use crate::api::common::require_admin_permission;

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
    #[allow(clippy::too_many_arguments)]
    #[oai(path = "/sessions", method = "get", operation_id = "get_sessions")]
    #[allow(clippy::too_many_arguments)]
    async fn api_get_all_sessions(
        &self,
        admin: AdminContext,
        offset: Query<Option<u64>>,
        limit: Query<Option<u64>>,
        active_only: Query<Option<bool>>,
        logged_in_only: Query<Option<bool>>,
        username: Query<Option<String>>,
    ) -> poem::Result<GetSessionsResponse> {
        use warpgate_db_entities::Session;

        admin.require(AdminPermission::SessionsView)?;

        let db = &admin.services().db;
        let mut q = Session::Entity::find().order_by_desc(Session::Column::Started);

        if active_only.unwrap_or(false) {
            q = q.filter(Session::Column::Ended.is_null());
        }
        if logged_in_only.unwrap_or(false) {
            q = q.filter(Session::Column::Username.is_not_null());
        }
        if let Some(username_filter) = username.as_ref() {
            q = q.filter(
                Expr::expr(Func::lower(Expr::col(Session::Column::Username)))
                    .eq(username_filter.to_lowercase()),
            );
        }

        Ok(GetSessionsResponse::Ok(Json(
            PaginatedResponse::new(
                q,
                PaginationParams {
                    limit: *limit,
                    offset: *offset,
                },
                db,
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
        admin: ClusterOrAdminContext,
        session: &Session,
        req: &poem::Request,
        /// Close only this node's own sessions instead of the whole cluster's.
        /// Set on cluster-forwarded copies of the request.
        local_only: Query<Option<bool>>,
    ) -> poem::Result<CloseAllSessionsResponse> {
        admin.require(AdminPermission::SessionsTerminate)?;

        {
            let state = admin.services().state.lock().await;
            for s in state.sessions.values() {
                s.lock().await.handle.close();
            }
        }

        session.purge();

        // A session's handle lives only on the node owning its connection, so
        // the request goes out to every other node too.
        if !local_only.unwrap_or(false) {
            close_on_peers(&admin, req).await?;
        }

        Ok(CloseAllSessionsResponse::Ok)
    }
}

/// Forward the close-all request to every other registered cluster node.
async fn close_on_peers(
    ctx: &AuthenticatedRequestContext,
    req: &poem::Request,
) -> poem::Result<()> {
    let services = ctx.services();
    let peers = Node::Entity::find()
        .filter(Node::Column::Id.ne(services.cluster.node_id))
        .all(&services.db)
        .await
        .map_err(WarpgateError::from)?;

    // `local_only` stops the peers from fanning out again
    let path = format!("{}?local_only=true", req.original_uri().path());

    let mut failed = vec![];
    for peer in peers {
        let hostname = peer.hostname.clone();
        match forward_http_to(ctx, req, &path, peer.into(), &services.cluster_token).await {
            Ok(response) if response.status() == StatusCode::CREATED => {}
            Ok(response) => {
                let status = response.status();
                warn!(node = %hostname, %status, "Failed to close sessions on a cluster node");
                failed.push(hostname);
            }
            Err(error) => {
                warn!(node = %hostname, %error, "Failed to close sessions on a cluster node");
                failed.push(hostname);
            }
        }
    }

    if failed.is_empty() {
        Ok(())
    } else {
        Err(poem::Error::from_string(
            format!("Failed to close sessions on: {}", failed.join(", ")),
            StatusCode::BAD_GATEWAY,
        ))
    }
}

#[handler]
pub async fn api_get_sessions_changes_stream(
    ctx: Data<&AuthenticatedRequestContext>,
    ws: WebSocket,
) -> Result<impl IntoResponse, WarpgateError> {
    require_admin_permission(&ctx, Some(AdminPermission::SessionsView)).await?;

    let mut receiver = ctx.services().state.lock().await.subscribe();

    Ok(ws
        .on_upgrade(|socket| async move {
            let (mut sink, _) = socket.split();

            while receiver.recv().await.is_ok() {
                sink.send(Message::Text("".into())).await?;
            }

            Ok::<(), anyhow::Error>(())
        })
        .into_response())
}
