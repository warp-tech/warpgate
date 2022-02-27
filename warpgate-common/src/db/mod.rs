use anyhow::Result;
use sea_orm::sea_query::Expr;
use sea_orm::{ConnectOptions, Database, DatabaseConnection, EntityTrait, QueryFilter};
use std::path::Path;
use std::time::Duration;
use warpgate_db_migrations::{Migrator, MigratorTrait};

use crate::WarpgateConfig;

pub async fn connect_to_db(config: &WarpgateConfig) -> Result<DatabaseConnection> {
    if config.database_url.ends_with(".sqlite3") {
        if let Some(parent) = Path::new(&config.database_url).parent() {
            std::fs::create_dir_all(parent)?
        }
    }
    let mut opt = ConnectOptions::new(config.database_url.clone());
    opt.max_connections(100)
        .min_connections(5)
        .connect_timeout(Duration::from_secs(8))
        .idle_timeout(Duration::from_secs(8))
        .max_lifetime(Duration::from_secs(8))
        .sqlx_logging(true);

    let connection = Database::connect(opt).await?;

    Migrator::up(&connection, None).await?;

    Ok(connection)
}

pub async fn sanitize_db(db: &mut DatabaseConnection) -> Result<()> {
    use sea_orm::ActiveValue::Set;
    use warpgate_db_entities::Session;

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
