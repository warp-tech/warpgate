use std::time::Duration;

use anyhow::Result;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ConnectOptions, Database, DatabaseConnection, EntityTrait, QueryFilter, TransactionTrait,
};
use warpgate_db_entities::LogEntry;
use warpgate_db_migrations::migrate_database;

use crate::helpers::fs::secure_file;
use crate::WarpgateConfig;

pub async fn connect_to_db(config: &WarpgateConfig) -> Result<DatabaseConnection> {
    let mut url = url::Url::parse(&config.store.database_url.expose_secret()[..])?;
    if url.scheme() == "sqlite" {
        let path = url.path();
        let mut abs_path = config.paths_relative_to.clone();
        abs_path.push(path);
        abs_path.push("db.sqlite3");

        if let Some(parent) = abs_path.parent() {
            std::fs::create_dir_all(parent)?
        }

        url.set_path(
            abs_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Failed to convert database path to string"))?,
        );

        url.set_query(Some("mode=rwc"));

        let db = Database::connect(ConnectOptions::new(url.to_string())).await?;
        db.begin().await?.commit().await?;
        drop(db);

        secure_file(&abs_path)?;
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

pub async fn sanitize_db(db: &mut DatabaseConnection) -> Result<()> {
    use sea_orm::ActiveValue::Set;
    use warpgate_db_entities::{Recording, Session};

    Recording::Entity::update_many()
        .set(Recording::ActiveModel {
            ended: Set(Some(chrono::Utc::now())),
            ..Default::default()
        })
        .filter(Expr::col(Recording::Column::Ended).is_null())
        .exec(db)
        .await?;

    Session::Entity::update_many()
        .set(Session::ActiveModel {
            ended: Set(Some(chrono::Utc::now())),
            ..Default::default()
        })
        .filter(Expr::col(Session::Column::Ended).is_null())
        .exec(db)
        .await?;

    Ok(())
}

pub async fn cleanup_db(db: &mut DatabaseConnection, retention: &Duration) -> Result<()> {
    use warpgate_db_entities::{Recording, Session};
    let cutoff = chrono::Utc::now() - chrono::Duration::from_std(*retention)?;

    LogEntry::Entity::delete_many()
        .filter(Expr::col(LogEntry::Column::Timestamp).lt(cutoff))
        .exec(db)
        .await?;

    Recording::Entity::delete_many()
        .filter(Expr::col(Session::Column::Ended).is_not_null())
        .filter(Expr::col(Session::Column::Ended).lt(cutoff))
        .exec(db)
        .await?;

    Session::Entity::delete_many()
        .filter(Expr::col(Session::Column::Ended).is_not_null())
        .filter(Expr::col(Session::Column::Ended).lt(cutoff))
        .exec(db)
        .await?;

    Ok(())
}
