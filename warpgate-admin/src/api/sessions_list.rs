use std::collections::HashMap;

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
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect,
};
use tracing::warn;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::{TargetSessionSnapshot, UserSessionSnapshot};
use warpgate_db_entities::{Node, TargetSession, UserSession};

use super::pagination::PaginatedResponse;
use super::{AdminContext, ClusterOrAdminContext};
use crate::api::cluster_proxy::fan_out_to_peers;
use crate::api::common::require_admin_permission;

pub struct Api;

#[derive(ApiResponse)]
enum GetSessionsResponse {
    #[oai(status = 200)]
    Ok(Json<PaginatedResponse<UserSessionSnapshot>>),
}

#[derive(ApiResponse)]
enum CloseAllSessionsResponse {
    #[oai(status = 201)]
    Ok,
}

#[OpenApi]
impl Api {
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
        admin.require(AdminPermission::SessionsView)?;

        let db = &admin.services().db;
        let mut q = UserSession::Entity::find().order_by_desc(UserSession::Column::Started);

        if active_only.unwrap_or(false) {
            q = q.filter(UserSession::Column::Ended.is_null());
        }
        if logged_in_only.unwrap_or(false) {
            q = q.filter(UserSession::Column::Username.is_not_null());
        }
        if let Some(username_filter) = username.as_ref() {
            q = q.filter(
                Expr::expr(Func::lower(Expr::col(UserSession::Column::Username)))
                    .eq(username_filter.to_lowercase()),
            );
        }

        let offset = offset.unwrap_or(0);
        let limit = limit.unwrap_or(100);
        let total = q.clone().count(db).await.map_err(WarpgateError::from)?;
        let parents = q
            .offset(offset)
            .limit(limit)
            .all(db)
            .await
            .map_err(WarpgateError::from)?;
        let snapshots = user_session_snapshots(db, parents).await?;

        Ok(GetSessionsResponse::Ok(Json(
            PaginatedResponse::from_parts(snapshots, offset, total),
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
            let user_states = {
                let state = admin.services().state.lock().await;
                state.user_sessions.values().cloned().collect::<Vec<_>>()
            };
            for state in user_states {
                state.lock().await.handle.close();
            }
        }

        session.purge();

        // A session's handle lives only on the node owning its connection, so
        // the request goes out to every other node too.
        if !local_only.unwrap_or(false) {
            close_on_peers(&admin, req).await;
        }

        Ok(CloseAllSessionsResponse::Ok)
    }
}

pub(super) async fn user_session_snapshots(
    db: &DatabaseConnection,
    parents: Vec<UserSession::Model>,
) -> Result<Vec<UserSessionSnapshot>, WarpgateError> {
    let parent_ids = parents.iter().map(|session| session.id).collect::<Vec<_>>();
    let targets = if parent_ids.is_empty() {
        vec![]
    } else {
        TargetSession::Entity::find()
            .filter(TargetSession::Column::UserSessionId.is_in(parent_ids))
            .order_by_desc(TargetSession::Column::Started)
            .all(db)
            .await?
    };

    let mut node_ids = parents
        .iter()
        .map(|session| session.node_id)
        .chain(targets.iter().map(|session| session.node_id))
        .collect::<Vec<_>>();
    node_ids.sort_unstable();
    node_ids.dedup();
    let node_names = if node_ids.is_empty() {
        HashMap::new()
    } else {
        Node::Entity::find()
            .filter(Node::Column::Id.is_in(node_ids))
            .all(db)
            .await?
            .into_iter()
            .map(|node| (node.id, node.hostname))
            .collect::<HashMap<_, _>>()
    };

    let mut targets_by_parent: HashMap<_, Vec<TargetSessionSnapshot>> = HashMap::new();
    for target in targets {
        let parent_id = target.user_session_id;
        let mut snapshot: TargetSessionSnapshot = target.into();
        snapshot.node_hostname = node_names.get(&snapshot.node_id).cloned();
        targets_by_parent
            .entry(parent_id)
            .or_default()
            .push(snapshot);
    }

    Ok(parents
        .into_iter()
        .map(|parent| {
            let mut snapshot: UserSessionSnapshot = parent.into();
            snapshot.node_hostname = node_names.get(&snapshot.node_id).cloned();
            snapshot.target_sessions = targets_by_parent.remove(&snapshot.id.0).unwrap_or_default();
            snapshot
        })
        .collect())
}

/// Forward the close-all request to every other registered cluster node.
///
/// Best effort: a node's sessions get marked ended in the database anyway, so an
/// unreachable peer is logged, not raised.
async fn close_on_peers(ctx: &AuthenticatedRequestContext, req: &poem::Request) {
    // `local_only` stops the peers from fanning out again
    let path = format!("{}?local_only=true", req.original_uri().path());

    for (hostname, response) in fan_out_to_peers(ctx, req, &path).await {
        if response.status() != StatusCode::CREATED {
            let status = response.status();
            warn!(node = %hostname, %status, "Failed to close sessions on a cluster node");
        }
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

#[cfg(test)]
mod tests {
    use sea_orm::ActiveValue::Set;
    use sea_orm::{ActiveModelTrait, Database};
    use time::OffsetDateTime;
    use uuid::Uuid;
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
    use warpgate_db_migrations::migrate_database;

    use super::*;

    #[tokio::test]
    async fn user_session_snapshot_contains_its_target_sessions() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let parent_id = Uuid::new_v4();
        let node_id = Uuid::new_v4();
        let parent = UserSession::ActiveModel {
            id: Set(parent_id),
            username: Set(Some("alice".into())),
            user_id: Set(Some(Uuid::new_v4())),
            remote_address: Set("127.0.0.1:22".into()),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            protocol: Set("SSH".into()),
            node_id: Set(node_id),
        }
        .insert(&db)
        .await
        .unwrap();

        for _ in 0..2 {
            TargetSession::ActiveModel {
                id: Set(Uuid::new_v4()),
                user_session_id: Set(parent_id),
                target_snapshot: Set(r#"{"name":"web"}"#.into()),
                target_id: Set(Uuid::new_v4()),
                started: Set(parent.started),
                ended: Set(None),
                ticket_id: Set(None),
                node_id: Set(node_id),
            }
            .insert(&db)
            .await
            .unwrap();
        }

        let snapshot = user_session_snapshots(&db, vec![parent])
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(snapshot.target_sessions.len(), 2);
    }
}
