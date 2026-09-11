use std::collections::HashMap;

use poem_openapi::param::Query;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::prelude::Expr;
use sea_orm::sea_query::Query as SeaQuery;
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, Select,
};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::{AdminPermission, TargetSessionId, UserSessionId, WarpgateError};
use warpgate_db_entities::{SessionCommand, TargetSession, UserSession};

use super::pagination::PaginatedResponse;
use super::AdminContext;
use crate::api::common::{case_insensitive_search, case_insensitive_search_expr};

pub struct Api;

#[derive(Object)]
struct SessionCommandSnapshot {
    id: Uuid,
    command: String,
    time: OffsetDateTime,
    target_session_id: TargetSessionId,
    /// The parent login session; `None` only in the race where it was deleted
    /// between listing the commands and fetching their parents.
    user_session_id: Option<UserSessionId>,
    username: Option<String>,
    /// Target name parsed from the session's target snapshot
    target_name: Option<String>,
}

#[derive(ApiResponse)]
enum SearchCommandsResponse {
    #[oai(status = 200)]
    Ok(Json<PaginatedResponse<SessionCommandSnapshot>>),
}

/// The command search query with all filters applied. Kept apart from the
/// handler so the filter composition can be tested without HTTP.
///
/// Commands are only recorded for SSH sessions opened after the command index
/// landed; detection itself is heuristic (see the command detector's module
/// docs in `warpgate-protocol-ssh`).
#[allow(clippy::too_many_arguments)]
pub(super) fn commands_query(
    q: Option<&str>,
    user: Option<&str>,
    target: Option<&str>,
    from: Option<OffsetDateTime>,
    to: Option<OffsetDateTime>,
) -> Select<SessionCommand::Entity> {
    let mut cmd_q = SessionCommand::Entity::find()
        .order_by_desc(SessionCommand::Column::Time)
        .order_by_desc(SessionCommand::Column::Id);

    if let Some(q) = q.filter(|s| !s.is_empty()) {
        cmd_q = cmd_q.filter(case_insensitive_search(q, [SessionCommand::Column::Command]));
    }
    if let Some(user) = user.filter(|s| !s.is_empty()) {
        cmd_q = cmd_q.filter(
            SessionCommand::Column::TargetSessionId.in_subquery(
                SeaQuery::select()
                    .column(TargetSession::Column::Id)
                    .from(TargetSession::Entity)
                    .and_where(
                        Expr::col(TargetSession::Column::UserSessionId).in_subquery(
                            SeaQuery::select()
                                .column(UserSession::Column::Id)
                                .from(UserSession::Entity)
                                .cond_where(case_insensitive_search(
                                    user,
                                    [UserSession::Column::Username],
                                ))
                                .to_owned(),
                        ),
                    )
                    .to_owned(),
            ),
        );
    }
    if let Some(target) = target.filter(|s| !s.is_empty()) {
        cmd_q = cmd_q.filter(
            SessionCommand::Column::TargetSessionId.in_subquery(
                SeaQuery::select()
                    .column(TargetSession::Column::Id)
                    .from(TargetSession::Entity)
                    // Like the sessions list search: a substring over the whole
                    // target snapshot, not just its name field.
                    .cond_where(case_insensitive_search_expr(
                        target,
                        [Expr::col(TargetSession::Column::TargetSnapshot).into()],
                    ))
                    .to_owned(),
            ),
        );
    }
    if let Some(from) = from {
        cmd_q = cmd_q.filter(SessionCommand::Column::Time.gte(from));
    }
    if let Some(to) = to {
        cmd_q = cmd_q.filter(SessionCommand::Column::Time.lte(to));
    }
    cmd_q
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/commands/search",
        method = "get",
        operation_id = "search_session_commands"
    )]
    #[allow(clippy::too_many_arguments)]
    async fn api_search_session_commands(
        &self,
        admin: AdminContext,
        q: Query<Option<String>>,
        user: Query<Option<String>>,
        target: Query<Option<String>>,
        from: Query<Option<OffsetDateTime>>,
        to: Query<Option<OffsetDateTime>>,
        offset: Query<Option<u64>>,
        limit: Query<Option<u64>>,
    ) -> poem::Result<SearchCommandsResponse> {
        admin.require(AdminPermission::SessionsView)?;

        let db = &admin.services().db;

        let cmd_q = commands_query(
            q.as_deref(),
            user.as_deref(),
            target.as_deref(),
            from.as_ref().copied(),
            to.as_ref().copied(),
        );

        let offset = offset.unwrap_or(0);
        let limit = limit.unwrap_or(100);
        let total = cmd_q
            .clone()
            .count(db)
            .await
            .map_err(WarpgateError::from)?;
        let commands = cmd_q
            .offset(offset)
            .limit(limit)
            .all(db)
            .await
            .map_err(WarpgateError::from)?;
        let snapshots = command_snapshots(db, commands).await?;

        Ok(SearchCommandsResponse::Ok(Json(
            PaginatedResponse::from_parts(snapshots, offset, total),
        )))
    }
}

/// Resolves each command's parent target and user session for display, the
/// same secondary-query shape as the sessions list.
async fn command_snapshots(
    db: &DatabaseConnection,
    commands: Vec<SessionCommand::Model>,
) -> Result<Vec<SessionCommandSnapshot>, WarpgateError> {
    let target_ids = commands
        .iter()
        .map(|command| command.target_session_id)
        .collect::<Vec<_>>();
    let targets = if target_ids.is_empty() {
        vec![]
    } else {
        TargetSession::Entity::find()
            .filter(TargetSession::Column::Id.is_in(target_ids))
            .all(db)
            .await?
    };

    let user_ids = targets
        .iter()
        .map(|target| target.user_session_id)
        .collect::<Vec<_>>();
    let user_sessions = if user_ids.is_empty() {
        vec![]
    } else {
        UserSession::Entity::find()
            .filter(UserSession::Column::Id.is_in(user_ids))
            .all(db)
            .await?
    };

    let targets_by_id = targets
        .into_iter()
        .map(|target| (target.id, target))
        .collect::<HashMap<_, _>>();
    let users_by_id = user_sessions
        .into_iter()
        .map(|session| (session.id, session))
        .collect::<HashMap<_, _>>();

    Ok(commands
        .into_iter()
        .map(|command| {
            let target = targets_by_id.get(&command.target_session_id);
            let user_session = target.and_then(|target| users_by_id.get(&target.user_session_id));
            SessionCommandSnapshot {
                id: command.id,
                command: command.command,
                time: command.time,
                target_session_id: command.target_session_id,
                user_session_id: target.map(|target| target.user_session_id),
                username: user_session.and_then(|session| session.username.clone()),
                target_name: target.and_then(|target| target_name(&target.target_snapshot)),
            }
        })
        .collect())
}

fn target_name(target_snapshot: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(target_snapshot)
        .ok()
        .and_then(|value| {
            value
                .get("name")
                .and_then(|name| name.as_str())
                .map(str::to_owned)
        })
}

#[cfg(test)]
mod tests {
    use sea_orm::ActiveValue::Set;
    use sea_orm::{ActiveModelTrait, Database};
    use uuid::Uuid;
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
    use warpgate_db_migrations::migrate_database;

    use super::*;

    /// Inserts one command row under a user session with the given username
    /// and target snapshot, and returns the command's id.
    async fn insert_command(
        db: &DatabaseConnection,
        username: Option<&str>,
        target_snapshot: &str,
        command: &str,
        time: OffsetDateTime,
    ) -> Uuid {
        let user_session_id = UserSessionId(Uuid::new_v4());
        UserSession::ActiveModel {
            id: Set(user_session_id),
            username: Set(username.map(str::to_string)),
            user_id: Set(username.map(|_| Uuid::new_v4())),
            remote_address: Set("127.0.0.1:22".into()),
            started: Set(time),
            ended: Set(None),
            protocol: Set("SSH".into()),
            node_id: Set(None),
            auth_state_node_id: Set(None),
        }
        .insert(db)
        .await
        .unwrap();

        let target_session_id = TargetSessionId(Uuid::new_v4());
        TargetSession::ActiveModel {
            id: Set(target_session_id),
            user_session_id: Set(user_session_id),
            target_snapshot: Set(target_snapshot.into()),
            target_id: Set(Uuid::new_v4()),
            started: Set(time),
            ended: Set(None),
            ticket_id: Set(None),
            node_id: Set(None),
        }
        .insert(db)
        .await
        .unwrap();

        let id = Uuid::new_v4();
        SessionCommand::ActiveModel {
            id: Set(id),
            target_session_id: Set(target_session_id),
            command: Set(command.into()),
            time: Set(time),
            node_id: Set(None),
        }
        .insert(db)
        .await
        .unwrap();
        id
    }

    async fn command_texts(
        db: &DatabaseConnection,
        q: Option<&str>,
        user: Option<&str>,
        target: Option<&str>,
        from: Option<OffsetDateTime>,
        to: Option<OffsetDateTime>,
    ) -> Vec<String> {
        commands_query(q, user, target, from, to)
            .all(db)
            .await
            .unwrap()
            .into_iter()
            .map(|command| command.command)
            .collect()
    }

    #[tokio::test]
    async fn q_matches_command_text_case_insensitively() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let now = OffsetDateTime::now_utc();
        insert_command(&db, Some("alice"), r#"{"name":"web"}"#, "curl --help", now).await;
        insert_command(&db, Some("bob"), r#"{"name":"db"}"#, "git status", now).await;

        let got = command_texts(&db, Some("CURL"), None, None, None, None).await;
        assert_eq!(got, vec!["curl --help"]);

        let got = command_texts(&db, Some("zzz"), None, None, None, None).await;
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn user_and_target_filters_join_through_the_parent_sessions() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let now = OffsetDateTime::now_utc();
        insert_command(&db, Some("alice"), r#"{"name":"web"}"#, "ls", now).await;
        insert_command(&db, Some("bob"), r#"{"name":"warpgate-ssh"}"#, "git status", now).await;

        let got = command_texts(&db, None, Some("alice"), None, None, None).await;
        assert_eq!(got, vec!["ls"]);

        let got = command_texts(&db, None, None, Some("SSH"), None, None).await;
        assert_eq!(got, vec!["git status"]);

        let got = command_texts(&db, None, Some("bob"), Some("warpgate-ssh"), None, None).await;
        assert_eq!(got, vec!["git status"]);

        let got = command_texts(&db, None, Some("bob"), Some("web"), None, None).await;
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn date_range_filters_by_command_time() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let base = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        insert_command(&db, Some("alice"), r#"{"name":"web"}"#, "old", base).await;
        insert_command(
            &db,
            Some("alice"),
            r#"{"name":"web"}"#,
            "middle",
            base + time::Duration::days(2),
        )
        .await;
        insert_command(
            &db,
            Some("alice"),
            r#"{"name":"web"}"#,
            "new",
            base + time::Duration::days(4),
        )
        .await;

        let got = command_texts(
            &db,
            None,
            None,
            None,
            Some(base + time::Duration::days(1)),
            Some(base + time::Duration::days(3)),
        )
        .await;
        assert_eq!(got, vec!["middle"]);
    }

    #[tokio::test]
    async fn snapshots_resolve_user_and_target_names() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let now = OffsetDateTime::now_utc();
        insert_command(&db, Some("alice"), r#"{"name":"web"}"#, "curl --help", now).await;

        let models = commands_query(Some("curl"), None, None, None, None)
            .all(&db)
            .await
            .unwrap();
        let snapshots = command_snapshots(&db, models).await.unwrap();
        assert_eq!(snapshots.len(), 1);
        let snapshot = snapshots.first().unwrap();
        assert_eq!(snapshot.username.as_deref(), Some("alice"));
        assert_eq!(snapshot.target_name.as_deref(), Some("web"));
        assert!(snapshot.user_session_id.is_some());
    }
}
