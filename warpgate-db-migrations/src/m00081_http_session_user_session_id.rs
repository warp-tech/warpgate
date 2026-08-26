use sea_orm::{ConnectionTrait, Order};
use sea_orm_migration::prelude::*;
use uuid::Uuid;

const BACKFILL_BATCH: u64 = 1000;

/// The user session id a stored browser session references, from its `data`
/// JSON (the `session_id` entry the HTTP session middleware writes).
fn user_session_id_from_data(data: &str) -> Option<Uuid> {
    serde_json::from_str::<serde_json::Value>(data)
        .ok()?
        .get("session_id")?
        .as_str()
        .and_then(|id| Uuid::parse_str(id).ok())
}

/// Adds a mirrored `user_session_id` column to `http_sessions` and fills it
/// from each row's `data` JSON, so that ending, revocation and the orphan
/// reaper are indexed SQL instead of JSON parsing. The column is re-mirrored
/// on every session save; the backfill covers rows written before it existed.
/// A row whose JSON carries no id backs no session and stays NULL.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("http_sessions"))
                    .add_column(ColumnDef::new(Alias::new("user_session_id")).uuid().null())
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_http_sessions_user_session_id")
                    .table(Alias::new("http_sessions"))
                    .col(Alias::new("user_session_id"))
                    .to_owned(),
            )
            .await?;

        backfill_user_session_ids(manager).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_http_sessions_user_session_id")
                    .table(Alias::new("http_sessions"))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("http_sessions"))
                    .drop_column(Alias::new("user_session_id"))
                    .to_owned(),
            )
            .await
    }
}

async fn backfill_user_session_ids(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();
    let backend = db.get_database_backend();

    let table = Alias::new("http_sessions");
    let id_col = Alias::new("id");
    let data_col = Alias::new("data");
    let user_session_id_col = Alias::new("user_session_id");

    // Keyset pagination over a stable order, so a batch boundary can't skip a
    // row the way an offset would once earlier rows are updated.
    let mut last_id: Option<String> = None;
    loop {
        let mut select = Query::select()
            .column(id_col.clone())
            .column(data_col.clone())
            .from(table.clone())
            .order_by(id_col.clone(), Order::Asc)
            .limit(BACKFILL_BATCH)
            .to_owned();
        if let Some(last_id) = &last_id {
            select.and_where(Expr::col(id_col.clone()).gt(last_id.clone()));
        }

        let rows = db.query_all(backend.build(&select)).await?;
        let done = (rows.len() as u64) < BACKFILL_BATCH;

        for row in &rows {
            let id: String = row.try_get("", "id")?;
            last_id = Some(id.clone());

            let data: String = row.try_get("", "data")?;
            let Some(user_session_id) = user_session_id_from_data(&data) else {
                continue;
            };
            let update = Query::update()
                .table(table.clone())
                .value(user_session_id_col.clone(), user_session_id)
                .and_where(Expr::col(id_col.clone()).eq(id))
                .to_owned();
            db.execute(backend.build(&update)).await?;
        }

        if done {
            return Ok(());
        }
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::{ConnectionTrait, Database, EntityTrait};
    use sea_orm_migration::MigratorTrait;
    use uuid::Uuid;
    use warpgate_db_entities::HttpSession;
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};

    use crate::Migrator;

    async fn stored_id(db: &sea_orm::DatabaseConnection, id: &str) -> Option<Uuid> {
        HttpSession::Entity::find_by_id(id.to_string())
            .one(db)
            .await
            .unwrap()
            .unwrap()
            .user_session_id
            .map(|id| id.0)
    }

    #[tokio::test]
    async fn backfills_the_mirrored_column_from_data_json() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, Some(80)).await.unwrap();

        let referenced = Uuid::new_v4();
        for (id, data) in [
            ("backed", format!(r#"{{"session_id":"{referenced}"}}"#)),
            ("empty", "{}".to_string()),
            ("broken", "not json".to_string()),
        ] {
            db.execute_unprepared(&format!(
                "INSERT INTO http_sessions (id, data, updated) \
                 VALUES ('{id}', '{data}', datetime('now'))",
            ))
            .await
            .unwrap();
        }

        Migrator::up(&db, None).await.unwrap();

        assert_eq!(stored_id(&db, "backed").await, Some(referenced));
        assert_eq!(stored_id(&db, "empty").await, None);
        assert_eq!(stored_id(&db, "broken").await, None);
    }
}
