use std::time::Duration;

use anyhow::Result;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ColumnTrait, ConnectOptions, Database, DatabaseConnection, EntityOrSelect, EntityTrait,
    QueryFilter, QuerySelect,
};
use time::OffsetDateTime;
use tracing::error;
use warpgate_common::helpers::fs::secure_file;
use warpgate_common::{GlobalParams, TargetSessionId, WarpgateConfig};
use warpgate_db_entities::Parameters::ConfigMigrationValues;
use warpgate_db_entities::{TargetSession, UserSession};
use warpgate_db_migrations::{migrate_database, migrate_database_down, migrate_database_up};

use crate::recordings::SessionRecordings;

/// Open a connection to the configured database without running migrations.
pub async fn connect_to_db(
    config: &WarpgateConfig,
    params: &GlobalParams,
) -> Result<DatabaseConnection> {
    let mut url = url::Url::parse(&config.store.database_url.expose_secret()[..])?;

    if url.scheme() == "sqlite" {
        let path = url.path();
        let mut abs_path = params.paths_relative_to().clone();
        abs_path.push(path);
        abs_path.push("db.sqlite3");

        if let Some(parent) = abs_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        url.set_path(
            abs_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Failed to convert database path to string"))?,
        );
        url.set_query(Some("mode=rwc"));

        let connection = connect_to_sqlite(url.as_str()).await?;

        if params.should_secure_files() {
            secure_file(&abs_path)?;
        }

        return Ok(connection);
    }

    let mut opt = ConnectOptions::new(url.to_string());
    opt.max_connections(100)
        .min_connections(5)
        .connect_timeout(Duration::from_secs(8))
        .idle_timeout(Duration::from_secs(8))
        .max_lifetime(Duration::from_secs(8))
        .sqlx_logging(true);

    let connection = Database::connect(opt).await?;

    Ok(connection)
}

/// WAL mode required to allow multiple concurrent writes to wait for each other
/// instead of failing
#[cfg(feature = "sqlite")]
async fn connect_to_sqlite(url: &str) -> Result<DatabaseConnection> {
    use std::str::FromStr;

    use sea_orm::SqlxSqliteConnector;
    use sea_orm::sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};

    let connect_options = SqliteConnectOptions::from_str(url)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(Duration::from_secs(30));

    let pool = SqlitePoolOptions::new()
        .max_connections(100)
        .min_connections(5)
        .acquire_timeout(Duration::from_secs(8))
        .idle_timeout(Duration::from_secs(8))
        .max_lifetime(Duration::from_secs(8))
        .connect_with(connect_options)
        .await?;

    Ok(SqlxSqliteConnector::from_sqlx_sqlite_pool(pool))
}

#[cfg(not(feature = "sqlite"))]
async fn connect_to_sqlite(_url: &str) -> Result<DatabaseConnection> {
    anyhow::bail!("SQLite support is not enabled in this build")
}

pub async fn connect_to_db_and_migrate(
    config: &WarpgateConfig,
    params: &GlobalParams,
) -> Result<DatabaseConnection> {
    let connection = connect_to_db(config, params).await?;
    // Publish the config-file settings that have moved into the parameters row
    // so the migrations can copy them into the DB; afterwards the config file's
    // copies are ignored.
    warpgate_db_entities::Parameters::set_config_migration_values(
        ConfigMigrationValues::from_config(config),
    );
    migrate_database(&connection).await?;
    Ok(connection)
}

/// Apply all pending migrations.
pub async fn migrate_all(connection: &DatabaseConnection) -> Result<()> {
    migrate_database(connection).await?;
    Ok(())
}

/// Apply `steps` pending migrations.
pub async fn migrate_up(connection: &DatabaseConnection, steps: u32) -> Result<()> {
    migrate_database_up(connection, steps).await?;
    Ok(())
}

/// Revert `steps` applied migrations.
pub async fn migrate_down(connection: &DatabaseConnection, steps: u32) -> Result<()> {
    migrate_database_down(connection, steps).await?;
    Ok(())
}

pub async fn cleanup_db(
    db: &DatabaseConnection,
    recordings: &SessionRecordings,
    retention: &Duration,
    audit_retention: &Duration,
) -> Result<()> {
    use warpgate_db_entities::{LogEntry, Recording, Ticket, TicketRequest};
    let audit_cutoff = OffsetDateTime::now_utc() - time::Duration::try_from(*audit_retention)?;
    let recording_cutoff = OffsetDateTime::now_utc() - time::Duration::try_from(*retention)?;

    LogEntry::Entity::delete_many()
        .filter(Expr::col(LogEntry::Column::Target).eq("audit"))
        .filter(Expr::col(LogEntry::Column::Timestamp).lt(audit_cutoff))
        .exec(db)
        .await?;

    LogEntry::Entity::delete_many()
        .filter(Expr::col(LogEntry::Column::Target).ne("audit"))
        .filter(Expr::col(LogEntry::Column::Timestamp).lt(recording_cutoff))
        .exec(db)
        .await?;

    {
        let active_ticket_ids = Ticket::Entity::find()
            .select()
            .column(Ticket::Column::Id)
            .filter(
                Expr::col(Ticket::Column::Expiry)
                    .is_null()
                    .or(Expr::col(Ticket::Column::Expiry).gt(OffsetDateTime::now_utc())),
            )
            .all(db)
            .await?
            .into_iter()
            .map(|x| x.id)
            .collect::<Vec<_>>();

        let mut request_deletion = TicketRequest::Entity::delete_many()
            .filter(Expr::col(TicketRequest::Column::Created).lt(audit_cutoff));

        if !active_ticket_ids.is_empty() {
            request_deletion = request_deletion.filter(
                Expr::col(TicketRequest::Column::TicketId)
                    .is_null()
                    .or(Expr::col(TicketRequest::Column::TicketId).is_not_in(active_ticket_ids)),
            );
        }

        request_deletion.exec(db).await?;
    }

    // Recordings are cleaned up by their parent session's `ended`, not their
    // own: a session ended abnormally (inactivity reaper, node shutdown, admin
    // close) never finalizes its recording, so `recording.ended` stays null and
    // the files would otherwise leak on disk forever.
    let expired_session_ids: Vec<TargetSessionId> = TargetSession::Entity::find()
        .filter(Expr::col(TargetSession::Column::Ended).is_not_null())
        .filter(Expr::col(TargetSession::Column::Ended).lt(recording_cutoff))
        .all(db)
        .await?
        .into_iter()
        .map(|s| s.id)
        .collect();

    if !expired_session_ids.is_empty() {
        let recordings_to_delete = Recording::Entity::find()
            .filter(
                Expr::col(Recording::Column::SessionId).is_in(expired_session_ids.iter().copied()),
            )
            .all(db)
            .await?;

        for recording in recordings_to_delete {
            if let Err(error) = recordings
                .remove(&recording.session_id, &recording.name)
                .await
            {
                error!(session=%recording.session_id, name=%recording.name, %error, "Failed to remove recording");
            }
        }

        // Recording rows are deleted explicitly rather than left to the FK
        // cascade so that the file removal above and the row removal form one
        // visible, ordered sequence.
        Recording::Entity::delete_many()
            .filter(
                Expr::col(Recording::Column::SessionId).is_in(expired_session_ids.iter().copied()),
            )
            .exec(db)
            .await?;

        TargetSession::Entity::delete_many()
            .filter(Expr::col(TargetSession::Column::Id).is_in(expired_session_ids))
            .exec(db)
            .await?;
    }

    // Keep user sessions who still have target sessions referencing them
    UserSession::Entity::delete_many()
        .filter(UserSession::Column::Ended.is_not_null())
        .filter(UserSession::Column::Ended.lt(recording_cutoff))
        .filter(
            UserSession::Column::Id.not_in_subquery(
                sea_orm::sea_query::Query::select()
                    .column(TargetSession::Column::UserSessionId)
                    .from(TargetSession::Entity)
                    .and_where(Expr::col(TargetSession::Column::UserSessionId).is_not_null())
                    .to_owned(),
            ),
        )
        .exec(db)
        .await?;

    Ok(())
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::ActiveValue::Set;
    use sea_orm::{Database, EntityTrait, PaginatorTrait};
    use uuid::Uuid;
    use warpgate_db_entities::HttpSession;
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
    use warpgate_db_migrations::migrate_database;

    use super::*;

    async fn open_session(db: &DatabaseConnection, node_id: Option<Uuid>) -> Uuid {
        let id = Uuid::new_v4();
        UserSession::Entity::insert(UserSession::ActiveModel {
            id: Set(warpgate_common::UserSessionId(id)),
            username: Set(Some("alice".into())),
            user_id: Set(Some(Uuid::new_v4())),
            remote_address: Set("127.0.0.1:1".into()),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            protocol: Set(if node_id.is_some() { "SSH" } else { "HTTP" }.into()),
            node_id: Set(node_id.map(warpgate_common::NodeId)),
            auth_state_node_id: Set(None),
        })
        .exec_without_returning(db)
        .await
        .unwrap();
        id
    }

    /// The close-everything sweep must reach sessions no node holds a handle
    /// for — that is its whole point — and log everyone out by deleting their
    /// stored browser sessions.
    #[tokio::test]
    async fn revoke_all_ends_detached_sessions_and_their_cookies() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();

        let direct = open_session(&db, Some(Uuid::new_v4())).await;
        let detached_http = open_session(&db, None).await;
        HttpSession::Entity::insert(HttpSession::ActiveModel {
            id: Set("cookie".into()),
            expires: Set(None),
            data: Set("{}".into()),
            updated: Set(OffsetDateTime::now_utc()),
            user_session_id: Set(Some(warpgate_common::UserSessionId(detached_http))),
        })
        .exec_without_returning(&db)
        .await
        .unwrap();

        UserSession::revoke_all(&db).await.unwrap();

        for id in [direct, detached_http] {
            assert!(
                UserSession::Entity::find_by_id(warpgate_common::UserSessionId(id))
                    .one(&db)
                    .await
                    .unwrap()
                    .unwrap()
                    .ended
                    .is_some()
            );
        }
        assert_eq!(HttpSession::Entity::find().count(&db).await.unwrap(), 0);
    }
}
