use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use percent_encoding::percent_decode_str;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ColumnTrait, ConnectOptions, Database, DatabaseConnection, DbErr, EntityOrSelect, EntityTrait,
    QueryFilter, QuerySelect, SqlErr,
};
use time::OffsetDateTime;
use tracing::error;
use warpgate_common::helpers::fs::secure_file;
use warpgate_common::{GlobalParams, TargetSessionId, WarpgateConfig};
use warpgate_db_entities::Parameters::ConfigMigrationValues;
use warpgate_db_entities::{TargetSession, UserSession};
use warpgate_db_migrations::{migrate_database, migrate_database_down, migrate_database_up};

use crate::recordings::SessionRecordings;

pub fn is_unique_violation(err: &DbErr) -> bool {
    matches!(err.sql_err(), Some(SqlErr::UniqueConstraintViolation(_)))
}

/// Open a connection to the configured database without running migrations.
pub async fn connect_to_db(
    config: &WarpgateConfig,
    params: &GlobalParams,
) -> Result<DatabaseConnection> {
    let url = url::Url::parse(&config.store.database_url.expose_secret()[..])?;

    if url.scheme() == "sqlite" {
        let abs_path = sqlite_db_path(&url, params.paths_relative_to())?;

        if let Some(parent) = abs_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let connection = connect_to_sqlite(&abs_path).await?;

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

/// The database file for a `sqlite:` URL: the URL path, percent-decoded once
/// (as sqlx does), resolved against `relative_to`, plus `db.sqlite3`.
///
/// The path is handed to SQLite as is, never through another URL, so it may
/// hold anything the OS allows (spaces, `%`, non-ASCII, Windows drive paths).
/// As in any URL, a `?` or `#` in the path must be written as `%3F` or `%23`.
fn sqlite_db_path(url: &url::Url, relative_to: &Path) -> Result<PathBuf> {
    let path = percent_decode_str(url.path()).decode_utf8()?;
    let mut abs_path = relative_to.to_path_buf();
    abs_path.push(&*path);
    abs_path.push("db.sqlite3");
    Ok(abs_path)
}

/// The `sqlite:` URL for a database in `dir`, which `connect_to_db` opens as
/// `dir/db.sqlite3`. Escapes `%`, `?` and `#`, which a URL would otherwise
/// read as an escape, the query and the fragment.
pub fn sqlite_url(dir: &Path) -> String {
    let dir = dir
        .to_string_lossy()
        .replace('%', "%25")
        .replace('?', "%3F")
        .replace('#', "%23");
    format!("sqlite:{dir}")
}

/// WAL mode required to allow multiple concurrent writes to wait for each other
/// instead of failing
#[cfg(feature = "sqlite")]
fn sqlite_connect_options(path: &Path) -> sea_orm::sqlx::sqlite::SqliteConnectOptions {
    use sea_orm::sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};

    SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(Duration::from_secs(30))
}

#[cfg(feature = "sqlite")]
async fn connect_to_sqlite(path: &Path) -> Result<DatabaseConnection> {
    use sea_orm::SqlxSqliteConnector;
    use sea_orm::sqlx::sqlite::SqlitePoolOptions;

    let pool = SqlitePoolOptions::new()
        .max_connections(100)
        .min_connections(5)
        .acquire_timeout(Duration::from_secs(8))
        .idle_timeout(Duration::from_secs(8))
        .max_lifetime(Duration::from_secs(8))
        .connect_with(sqlite_connect_options(path))
        .await?;

    Ok(SqlxSqliteConnector::from_sqlx_sqlite_pool(pool))
}

#[cfg(not(feature = "sqlite"))]
async fn connect_to_sqlite(_path: &Path) -> Result<DatabaseConnection> {
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
    use warpgate_db_entities::{
        LogEntry, Recording, SessionApprovalRequest, Ticket, TicketRequest,
    };
    let audit_cutoff = OffsetDateTime::now_utc() - time::Duration::try_from(*audit_retention)?;
    let recording_cutoff = OffsetDateTime::now_utc() - time::Duration::try_from(*retention)?;

    SessionApprovalRequest::delete_all_before(db, audit_cutoff).await?;

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
        open_session_for_user(db, node_id, Uuid::new_v4()).await
    }

    async fn open_session_for_user(
        db: &DatabaseConnection,
        node_id: Option<Uuid>,
        user_id: Uuid,
    ) -> Uuid {
        let id = Uuid::new_v4();
        UserSession::Entity::insert(UserSession::ActiveModel {
            id: Set(warpgate_common::UserSessionId(id)),
            username: Set(Some("alice".into())),
            user_id: Set(Some(user_id)),
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
            ..Default::default()
        })
        .exec_without_returning(&db)
        .await
        .unwrap();

        crate::SessionsFilter::All.revoke(&db).await.unwrap();

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

    /// Database directories setup may write, relative to the config directory
    /// or absolute.
    fn sqlite_dirs() -> Vec<PathBuf> {
        let mut dirs = vec![
            "data/db",
            "my data/db",
            "x#y/db",
            "100%/db",
            "%25/db",
            "q?r/db",
            "caf\u{e9}/\u{65e5}\u{672c}",
            "a/b/c/d",
            "../data/db",
        ];
        if cfg!(windows) {
            dirs.extend([
                r"data\db",
                r"C:\ProgramData\warpgate\db",
                r"D:\my data\wg #1\db",
                r"\\?\C:\ProgramData\warpgate\db",
                r"\\server\share\warpgate\db",
            ]);
        } else {
            dirs.extend(["/var/lib/warpgate/db", "/srv/my data/caf\u{e9}/db"]);
        }
        dirs.into_iter().map(PathBuf::from).collect()
    }

    /// The URL setup writes for a directory opens and secures exactly the
    /// database file in that directory.
    #[test]
    fn sqlite_url_round_trip() {
        let base = if cfg!(windows) {
            Path::new(r"C:\etc\warpgate")
        } else {
            Path::new("/etc/warpgate")
        };
        for dir in sqlite_dirs() {
            let database_url = sqlite_url(&dir);
            let url = url::Url::parse(&database_url).unwrap();
            let expected = base.join(&dir).join("db.sqlite3");
            let secured = sqlite_db_path(&url, base).unwrap();
            assert_eq!(secured, expected, "{database_url:?}");
            let options = sqlite_connect_options(&secured);
            assert_eq!(options.get_filename(), expected, "{database_url:?}");
        }
    }

    /// The same on disk: `connect_to_db` creates and secures the database
    /// where setup configured it.
    #[tokio::test]
    async fn connect_to_db_creates_the_configured_file() {
        let base = std::env::temp_dir().join(format!("warpgate-db-path-{}", Uuid::new_v4()));
        let params = GlobalParams::new(base.join("warpgate.yaml"), true).unwrap();
        for dir in ["my data/db", "caf\u{e9}/db", "%25/x#y"] {
            for dir in [PathBuf::from(dir), base.join(dir)] {
                let config = WarpgateConfig {
                    store: warpgate_common::WarpgateConfigStore {
                        database_url: warpgate_common::Secret::new(sqlite_url(&dir)),
                        ..Default::default()
                    },
                };
                let db = connect_to_db(&config, &params).await.unwrap();
                db.close().await.unwrap();
                let expected = base.join(&dir).join("db.sqlite3");
                assert!(expected.is_file(), "no {expected:?}");
            }
        }
        std::fs::remove_dir_all(&base).unwrap();
    }
}
