use data_encoding::HEXLOWER;
use sea_orm_migration::prelude::*;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Ticket and API token secrets are stored as SHA-256 digests so a database
/// leak does not yield usable credentials. The secrets are 32 random bytes,
/// so an unsalted deterministic digest is safe and keeps equality lookups.
#[derive(DeriveMigrationName)]
pub struct Migration;

fn index_name(table: &str) -> String {
    format!("idx_{table}_secret_hash")
}

async fn hash_column(manager: &SchemaManager<'_>, table_name: &str) -> Result<(), DbErr> {
    let db = manager.get_connection();
    let backend = db.get_database_backend();

    let table = Alias::new(table_name);
    let id_col = Alias::new("id");
    let secret_col = Alias::new("secret");
    let hash_col = Alias::new("secret_hash");

    let select = Query::select()
        .column(id_col.clone())
        .column(secret_col.clone())
        .from(table.clone())
        .to_owned();

    for row in db.query_all(backend.build(&select)).await? {
        let id: Uuid = row.try_get("", "id")?;
        let secret: String = row.try_get("", "secret")?;
        let hash = HEXLOWER.encode(&Sha256::digest(secret.as_bytes()));

        let update = Query::update()
            .table(table.clone())
            .value(secret_col.clone(), hash)
            .and_where(Expr::col(id_col.clone()).eq(id))
            .to_owned();
        db.execute(backend.build(&update)).await?;
    }

    manager
        .alter_table(
            Table::alter()
                .table(table.clone())
                .rename_column(secret_col, hash_col.clone())
                .to_owned(),
        )
        .await?;

    // Every ticket and API token presentation authenticates by looking the row
    // up by this hash, so it is on the hot path of an unauthenticated request.
    manager
        .create_index(
            Index::create()
                .name(index_name(table_name))
                .table(table)
                .col(hash_col)
                .to_owned(),
        )
        .await
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        hash_column(manager, "tickets").await?;
        hash_column(manager, "api_tokens").await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // The raw secrets are unrecoverable; only the schema change is reverted.
        for table in ["tickets", "api_tokens"] {
            manager
                .drop_index(
                    Index::drop()
                        .name(index_name(table))
                        .table(Alias::new(table))
                        .to_owned(),
                )
                .await?;
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new(table))
                        .rename_column(Alias::new("secret_hash"), Alias::new("secret"))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::{ConnectionTrait, Database, Statement};
    use sea_orm_migration::MigratorTrait;
    use sea_orm_migration::prelude::*;
    use uuid::Uuid;
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};

    use super::{Migration, index_name};
    use crate::Migrator;

    #[tokio::test]
    async fn hashes_existing_secrets_and_renames_the_column() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        let backend = db.get_database_backend();

        // Migrate up to just before this migration, then seed raw-secret rows.
        let all_migrations = Migrator::migrations();
        let this_migration_index = all_migrations
            .iter()
            .position(|m| m.name() == Migration.name())
            .expect("this migration must be registered in Migrator::migrations()");
        let steps = this_migration_index as u32;
        Migrator::up(&db, Some(steps)).await.unwrap();

        db.execute_unprepared("PRAGMA foreign_keys = OFF")
            .await
            .unwrap();
        let insert = Query::insert()
            .into_table(Alias::new("tickets"))
            .columns([
                Alias::new("id"),
                Alias::new("secret"),
                Alias::new("user_id"),
                Alias::new("description"),
                Alias::new("target_id"),
                Alias::new("self_service"),
                Alias::new("created"),
            ])
            .values_panic([
                Uuid::new_v4().into(),
                "topsecret".into(),
                Uuid::new_v4().into(),
                "".into(),
                Uuid::new_v4().into(),
                false.into(),
                "2026-01-01 00:00:00".into(),
            ])
            .to_owned();
        db.execute(backend.build(&insert)).await.unwrap();

        Migrator::up(&db, None).await.unwrap();

        let select = Query::select()
            .column(Alias::new("secret_hash"))
            .from(Alias::new("tickets"))
            .to_owned();
        let row = db.query_one(backend.build(&select)).await.unwrap().unwrap();
        let hash: String = row.try_get("", "secret_hash").unwrap();
        assert_eq!(
            hash,
            // SHA-256 of "topsecret"
            "53336a676c64c1396553b2b7c92f38126768827c93b64d9142069c10eda7a721"
        );

        // The lookup is on an unauthenticated hot path, so a seq scan here is a
        // DoS surface rather than just a slow query.
        for table in ["tickets", "api_tokens"] {
            let plan = db
                .query_one(Statement::from_string(
                    backend,
                    format!("EXPLAIN QUERY PLAN SELECT id FROM {table} WHERE secret_hash = 'x'"),
                ))
                .await
                .unwrap()
                .unwrap();
            let detail: String = plan.try_get("", "detail").unwrap();
            assert!(
                detail.contains(&index_name(table)),
                "{table} lookup did not use the index: {detail}"
            );
        }
    }
}
