use std::time::Duration;

use anyhow::Result;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ConnectOptions, Database, DatabaseConnection, EntityOrSelect, EntityTrait, ModelTrait,
    QueryFilter, QuerySelect, TransactionTrait,
};
use time::OffsetDateTime;
use tracing::error;
use warpgate_common::helpers::fs::secure_file;
use warpgate_common::{GlobalParams, WarpgateConfig, WarpgateError};
use warpgate_db_migrations::migrate_database;

use crate::recordings::SessionRecordings;

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

        let db = Database::connect(ConnectOptions::new(url.to_string())).await?;
        db.begin().await?.commit().await?;

        if params.should_secure_files() {
            secure_file(&abs_path)?;
        }
    }

    let mut opt = ConnectOptions::new(url.to_string());
    opt.max_connections(100)
        .min_connections(5)
        .connect_timeout(Duration::from_secs(8))
        .idle_timeout(Duration::from_secs(8))
        .max_lifetime(Duration::from_secs(8))
        .sqlx_logging(true);

    let connection = Database::connect(opt).await?;

    migrate_database(&connection).await?;
    Ok(connection)
}

pub async fn populate_db(
    db: &DatabaseConnection,
    _config: &mut WarpgateConfig,
) -> Result<(), WarpgateError> {
    use sea_orm::ActiveValue::Set;
    use warpgate_db_entities::{Recording, Session};

    Recording::Entity::update_many()
        .set(Recording::ActiveModel {
            ended: Set(Some(OffsetDateTime::now_utc())),
            ..Default::default()
        })
        .filter(Expr::col(Recording::Column::Ended).is_null())
        .exec(db)
        .await
        .map_err(WarpgateError::from)?;

    Session::Entity::update_many()
        .set(Session::ActiveModel {
            ended: Set(Some(OffsetDateTime::now_utc())),
            ..Default::default()
        })
        .filter(Expr::col(Session::Column::Ended).is_null())
        .exec(db)
        .await
        .map_err(WarpgateError::from)?;

    Ok(())
}

pub async fn cleanup_db(
    db: &DatabaseConnection,
    recordings: &SessionRecordings,
    retention: &Duration,
    audit_retention: &Duration,
) -> Result<()> {
    use warpgate_db_entities::{LogEntry, Recording, Session, Ticket, TicketRequest};
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

    let recordings_to_delete = Recording::Entity::find()
        .filter(Expr::col(Session::Column::Ended).is_not_null())
        .filter(Expr::col(Session::Column::Ended).lt(recording_cutoff))
        .all(db)
        .await?;

    for recording in recordings_to_delete {
        if let Err(error) = recordings
            .remove(&recording.session_id, &recording.name)
            .await
        {
            error!(session=%recording.session_id, name=%recording.name, %error, "Failed to remove recording");
        }
        recording.delete(db).await?;
    }

    Session::Entity::delete_many()
        .filter(Expr::col(Session::Column::Ended).is_not_null())
        .filter(Expr::col(Session::Column::Ended).lt(recording_cutoff))
        .exec(db)
        .await?;

    Ok(())
}
