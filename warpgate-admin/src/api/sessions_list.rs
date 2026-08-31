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
use sea_orm::sea_query::{Func, Query as SeaQuery};
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, Select,
};
use time::OffsetDateTime;
use tracing::warn;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::{TargetSessionSnapshot, UserSessionSnapshot};
use warpgate_db_entities::{Node, TargetSession, UserSession};

use super::pagination::PaginatedResponse;
use super::{AdminContext, ClusterOrAdminContext};
use crate::api::cluster_proxy::fan_out_to_peers_expecting;
use crate::api::common::{case_insensitive_search_expr, require_admin_permission};

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
        search: Query<Option<String>>,
        from: Query<Option<OffsetDateTime>>,
        to: Query<Option<OffsetDateTime>>,
        protocol: Query<Option<String>>,
    ) -> poem::Result<GetSessionsResponse> {
        admin.require(AdminPermission::SessionsView)?;

        let db = &admin.services().db;

        let q = sessions_query(
            active_only.unwrap_or(false),
            logged_in_only.unwrap_or(false),
            username.as_deref(),
            search.as_deref(),
            from.as_ref().copied(),
            to.as_ref().copied(),
            protocol.as_deref(),
        );

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
    ) -> poem::Result<CloseAllSessionsResponse> {
        admin.require(AdminPermission::SessionsTerminate)?;

        let intra_cluster = admin.is_intra_cluster_request();
        if !intra_cluster {
            // kill DB sessions before killing handles to avoid a race
            UserSession::revoke_all(&admin.services().db)
                .await
                .map_err(poem::error::InternalServerError)?;
        }

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

        if !intra_cluster {
            for (node, status) in fan_out_to_peers_expecting(&admin, req, StatusCode::CREATED).await
            {
                warn!(%node, %status, "Failed to close sessions on a cluster node");
            }
        }

        Ok(CloseAllSessionsResponse::Ok)
    }
}

/// The sessions list query with all list filters applied. Kept apart from the
/// handler so the filter composition can be tested without HTTP.
///
/// `search` is free text over the username and the target names. Target names
/// live in `target_sessions.target_snapshot` (a JSON document stored as text),
/// so the match is a case-insensitive substring over the whole snapshot: a term
/// that only occurs in another field of the snapshot (e.g. an option value)
/// also matches. Precise name extraction (`json_extract`) was considered and
/// left out to stay backend-agnostic — see the session search PR discussion.
pub(super) fn sessions_query(
    active_only: bool,
    logged_in_only: bool,
    username: Option<&str>,
    search: Option<&str>,
    from: Option<OffsetDateTime>,
    to: Option<OffsetDateTime>,
    protocol: Option<&str>,
) -> Select<UserSession::Entity> {
    // sort by both as a sorting tiebreaker
    let mut q = UserSession::Entity::find()
        .order_by_desc(UserSession::Column::Started)
        .order_by_desc(UserSession::Column::Id);

    if active_only {
        q = q.filter(UserSession::Column::Ended.is_null());
    }
    if logged_in_only {
        q = q.filter(UserSession::Column::Username.is_not_null());
    }
    if let Some(username_filter) = username {
        q = q.filter(
            Expr::expr(Func::lower(Expr::col(UserSession::Column::Username)))
                .eq(username_filter.to_lowercase()),
        );
    }
    if let Some(from) = from {
        q = q.filter(UserSession::Column::Started.gte(from));
    }
    if let Some(to) = to {
        q = q.filter(UserSession::Column::Started.lte(to));
    }
    if let Some(protocol_filter) = protocol {
        q = q.filter(
            Expr::expr(Func::lower(Expr::col(UserSession::Column::Protocol)))
                .eq(protocol_filter.to_lowercase()),
        );
    }
    if let Some(search) = search.filter(|s| !s.is_empty()) {
        // OR of "username matches" and "any target session's snapshot matches",
        // spelled out as expressions because the shared search helpers return
        // opaque conditions that can't be composed with `Condition::add`.
        let pattern = format!("%{}%", search.to_lowercase());
        let username_match = Expr::expr(Func::lower(Expr::col(UserSession::Column::Username)))
            .like(pattern.clone());
        let target_match = UserSession::Column::Id.in_subquery(
            SeaQuery::select()
                .column(TargetSession::Column::UserSessionId)
                .from(TargetSession::Entity)
                .cond_where(case_insensitive_search_expr(
                    search,
                    [Expr::col(TargetSession::Column::TargetSnapshot).into()],
                ))
                .to_owned(),
        );
        q = q.filter(username_match.or(target_match));
    }
    q
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
        .filter_map(|session| session.node_id)
        .chain(targets.iter().filter_map(|session| session.node_id))
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

    let mut targets_by_parent: HashMap<_, Vec<_>> = HashMap::new();
    for target in targets {
        let parent_id = target.user_session_id;
        let mut snapshot: TargetSessionSnapshot = target.into();
        snapshot.node_hostname = snapshot.node_id.and_then(|id| node_names.get(&id).cloned());
        targets_by_parent
            .entry(parent_id)
            .or_default()
            .push(snapshot);
    }

    Ok(parents
        .into_iter()
        .map(|parent| {
            let mut snapshot: UserSessionSnapshot = parent.into();
            snapshot.node_hostname = snapshot.node_id.and_then(|id| node_names.get(&id).cloned());
            snapshot.target_sessions = targets_by_parent.remove(&snapshot.id).unwrap_or_default();
            snapshot
        })
        .collect())
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

            // TODO cluster broadcast

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
        let parent_id = warpgate_common::UserSessionId(Uuid::new_v4());
        let node_id = warpgate_common::NodeId(Uuid::new_v4());
        let parent = UserSession::ActiveModel {
            id: Set(parent_id),
            username: Set(Some("alice".into())),
            user_id: Set(Some(Uuid::new_v4())),
            remote_address: Set("127.0.0.1:22".into()),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            protocol: Set("SSH".into()),
            node_id: Set(Some(node_id)),
            auth_state_node_id: Set(None),
        }
        .insert(&db)
        .await
        .unwrap();

        for _ in 0..2 {
            TargetSession::ActiveModel {
                id: Set(warpgate_common::TargetSessionId(Uuid::new_v4())),
                user_session_id: Set(parent_id),
                target_snapshot: Set(r#"{"name":"web"}"#.into()),
                target_id: Set(Uuid::new_v4()),
                started: Set(parent.started),
                ended: Set(None),
                ticket_id: Set(None),
                node_id: Set(Some(node_id)),
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

    /// Inserts one user session with an optional target name snapshot and
    /// returns its id.
    async fn insert_session(
        db: &DatabaseConnection,
        username: Option<&str>,
        started: OffsetDateTime,
        protocol: &str,
        target_snapshot: Option<&str>,
    ) -> warpgate_common::UserSessionId {
        let id = warpgate_common::UserSessionId(Uuid::new_v4());
        UserSession::ActiveModel {
            id: Set(id),
            username: Set(username.map(str::to_string)),
            user_id: Set(username.map(|_| Uuid::new_v4())),
            remote_address: Set("127.0.0.1:22".into()),
            started: Set(started),
            ended: Set(None),
            protocol: Set(protocol.into()),
            node_id: Set(None),
            auth_state_node_id: Set(None),
        }
        .insert(db)
        .await
        .unwrap();
        if let Some(snapshot) = target_snapshot {
            TargetSession::ActiveModel {
                id: Set(warpgate_common::TargetSessionId(Uuid::new_v4())),
                user_session_id: Set(id),
                target_snapshot: Set(snapshot.into()),
                target_id: Set(Uuid::new_v4()),
                started: Set(started),
                ended: Set(None),
                ticket_id: Set(None),
                node_id: Set(None),
            }
            .insert(db)
            .await
            .unwrap();
        }
        id
    }

    async fn ids(
        db: &DatabaseConnection,
        q: Select<UserSession::Entity>,
    ) -> Vec<warpgate_common::UserSessionId> {
        q.all(db).await.unwrap().into_iter().map(|s| s.id).collect()
    }

    #[tokio::test]
    async fn date_range_filters_by_session_start() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let base = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();

        let old = insert_session(&db, Some("alice"), base, "SSH", None).await;
        let middle =
            insert_session(&db, Some("bob"), base + time::Duration::days(2), "SSH", None).await;
        let new =
            insert_session(&db, Some("carol"), base + time::Duration::days(4), "SSH", None).await;

        let from = base + time::Duration::days(1);
        let to = base + time::Duration::days(3);
        let got = ids(
            &db,
            sessions_query(false, false, None, None, Some(from), Some(to), None),
        )
        .await;
        assert_eq!(got, vec![middle]);

        let got = ids(&db, sessions_query(false, false, None, None, Some(from), None, None)).await;
        assert_eq!(got, vec![new, middle]);

        let got = ids(&db, sessions_query(false, false, None, None, None, Some(to), None)).await;
        assert_eq!(got, vec![middle, old]);
    }

    #[tokio::test]
    async fn search_matches_username_or_target_name() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let now = OffsetDateTime::now_utc();

        let alice = insert_session(&db, Some("alice"), now, "SSH", None).await;
        let target_match = insert_session(
            &db,
            Some("bob"),
            now,
            "SSH",
            Some(r#"{"name":"warpgate-ssh"}"#),
        )
        .await;
        let _neither = insert_session(&db, Some("carol"), now, "HTTP", Some(r#"{"name":"web"}"#))
            .await;

        // Matches the username of one session...
        let got = ids(&db, sessions_query(false, false, None, Some("ALICE"), None, None, None))
            .await;
        assert_eq!(got, vec![alice]);
        // ...or the target name of another, case-insensitively.
        let got = ids(&db, sessions_query(false, false, None, Some("ssh"), None, None, None))
            .await;
        assert_eq!(got, vec![target_match]);
        // A term that matches neither field matches nothing.
        let got = ids(&db, sessions_query(false, false, None, Some("zzz"), None, None, None)).await;
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn protocol_filter_matches_case_insensitively() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let now = OffsetDateTime::now_utc();

        let ssh = insert_session(&db, Some("alice"), now, "SSH", None).await;
        let _http = insert_session(&db, Some("bob"), now, "HTTP", None).await;

        let got = ids(&db, sessions_query(false, false, None, None, None, None, Some("ssh"))).await;
        assert_eq!(got, vec![ssh]);
    }

    #[tokio::test]
    async fn no_filters_returns_everything() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let now = OffsetDateTime::now_utc();

        insert_session(&db, Some("alice"), now, "SSH", Some(r#"{"name":"web"}"#)).await;
        insert_session(&db, None, now, "HTTP", None).await;

        let got = ids(&db, sessions_query(false, false, None, None, None, None, None)).await;
        assert_eq!(got.len(), 2);
    }
}
