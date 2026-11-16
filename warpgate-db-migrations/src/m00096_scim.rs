//! SCIM provisioning: a table of provisioning tokens, the columns SCIM needs on
//! users and roles, and creation/modification timestamps on both.
//!
//! The timestamps are added nullable and backfilled with the migration time:
//! SQLite cannot add a NOT NULL column whose default is not a constant, and a
//! literal default would need a different spelling per backend. New rows are
//! stamped by the entities' `before_save` hook.
use sea_orm::{ConnectionTrait, Schema};
use sea_orm_migration::prelude::*;

pub mod scim_token {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "scim_tokens")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub label: String,
        pub secret_hash: String,
        pub sso_provider: Option<String>,
        pub created: OffsetDateTime,
        pub expiry: Option<OffsetDateTime>,
        pub last_used: Option<OffsetDateTime>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[derive(DeriveMigrationName)]
pub struct Migration;

const USERS: &str = "users";
const ROLES: &str = "roles";
const CREATED_AT: &str = "created_at";
const UPDATED_AT: &str = "updated_at";
const SCIM_EXTERNAL_ID: &str = "scim_external_id";

fn external_id_index(table: &str) -> String {
    format!("idx_{table}_scim_external_id")
}

async fn add_column(
    manager: &SchemaManager<'_>,
    table: &str,
    column: ColumnDef,
) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(Alias::new(table))
                .add_column(column)
                .to_owned(),
        )
        .await
}

async fn drop_column(manager: &SchemaManager<'_>, table: &str, name: &str) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(Alias::new(table))
                .drop_column(Alias::new(name))
                .to_owned(),
        )
        .await
}

/// Timestamps + external id, shared by `users` and `roles`.
async fn add_scim_columns(manager: &SchemaManager<'_>, table: &str) -> Result<(), DbErr> {
    add_column(
        manager,
        table,
        ColumnDef::new(Alias::new(SCIM_EXTERNAL_ID))
            .string()
            .null()
            .to_owned(),
    )
    .await?;
    for name in [CREATED_AT, UPDATED_AT] {
        add_column(
            manager,
            table,
            ColumnDef::new(Alias::new(name))
                .timestamp_with_time_zone()
                .null()
                .to_owned(),
        )
        .await?;
    }

    let db = manager.get_connection();
    let backfill = Query::update()
        .table(Alias::new(table))
        .value(Alias::new(CREATED_AT), Expr::current_timestamp())
        .value(Alias::new(UPDATED_AT), Expr::current_timestamp())
        .to_owned();
    db.execute(db.get_database_backend().build(&backfill))
        .await?;

    // IdPs look resources up by externalId during every sync.
    manager
        .create_index(
            Index::create()
                .name(external_id_index(table))
                .table(Alias::new(table))
                .col(Alias::new(SCIM_EXTERNAL_ID))
                .to_owned(),
        )
        .await
}

async fn drop_scim_columns(manager: &SchemaManager<'_>, table: &str) -> Result<(), DbErr> {
    manager
        .drop_index(
            Index::drop()
                .name(external_id_index(table))
                .table(Alias::new(table))
                .to_owned(),
        )
        .await?;
    for name in [UPDATED_AT, CREATED_AT, SCIM_EXTERNAL_ID] {
        drop_column(manager, table, name).await?;
    }
    Ok(())
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let schema = Schema::new(manager.get_database_backend());
        manager
            .create_table(schema.create_table_from_entity(scim_token::Entity))
            .await?;
        // Every SCIM request authenticates by looking the token up by this hash.
        manager
            .create_index(
                Index::create()
                    .name("idx_scim_tokens_secret_hash")
                    .table(scim_token::Entity)
                    .col(scim_token::Column::SecretHash)
                    .to_owned(),
            )
            .await?;

        add_column(
            manager,
            USERS,
            ColumnDef::new(Alias::new("enabled"))
                .boolean()
                .not_null()
                .default(true)
                .to_owned(),
        )
        .await?;
        add_column(
            manager,
            USERS,
            ColumnDef::new(Alias::new("scim_attributes"))
                .text()
                .null()
                .to_owned(),
        )
        .await?;
        add_scim_columns(manager, USERS).await?;
        add_scim_columns(manager, ROLES).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        drop_scim_columns(manager, ROLES).await?;
        drop_scim_columns(manager, USERS).await?;
        drop_column(manager, USERS, "scim_attributes").await?;
        drop_column(manager, USERS, "enabled").await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_scim_tokens_secret_hash")
                    .table(scim_token::Entity)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(scim_token::Entity).to_owned())
            .await
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::{ConnectionTrait, Database, Statement};
    use sea_orm_migration::MigratorTrait;
    use sea_orm_migration::prelude::{Alias, Query};
    use uuid::Uuid;
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};

    use crate::Migrator;

    /// Rows that predate the migration get the migration time as both
    /// timestamps and stay enabled, so nothing changes for existing installs.
    #[tokio::test]
    async fn existing_rows_are_backfilled_and_enabled() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        let before = Migrator::migrations()
            .iter()
            .position(|migration| migration.name() == "m00096_scim")
            .unwrap();
        Migrator::up(&db, Some(u32::try_from(before).unwrap()))
            .await
            .unwrap();

        let backend = db.get_database_backend();
        db.execute(
            backend.build(
                Query::insert()
                    .into_table(Alias::new("users"))
                    .columns(["id", "username", "credential_policy", "description"].map(Alias::new))
                    .values_panic([
                        Uuid::new_v4().into(),
                        "alice".into(),
                        "null".into(),
                        "".into(),
                    ]),
            ),
        )
        .await
        .unwrap();
        db.execute(
            backend.build(
                Query::insert()
                    .into_table(Alias::new("roles"))
                    .columns(["id", "name", "description", "is_default"].map(Alias::new))
                    .values_panic([Uuid::new_v4().into(), "ops".into(), "".into(), false.into()]),
            ),
        )
        .await
        .unwrap();

        Migrator::up(&db, None).await.unwrap();

        for table in ["users", "roles"] {
            let row = db
                .query_one(Statement::from_string(
                    backend,
                    format!(
                        "SELECT created_at IS NOT NULL AS has_created, updated_at IS NOT NULL AS has_updated, scim_external_id FROM {table}"
                    ),
                ))
                .await
                .unwrap()
                .unwrap();
            assert!(row.try_get::<bool>("", "has_created").unwrap(), "{table}");
            assert!(row.try_get::<bool>("", "has_updated").unwrap(), "{table}");
            assert_eq!(
                row.try_get::<Option<String>>("", "scim_external_id")
                    .unwrap(),
                None
            );
        }
        let row = db
            .query_one(Statement::from_string(
                backend,
                "SELECT enabled, scim_attributes FROM users",
            ))
            .await
            .unwrap()
            .unwrap();
        assert!(row.try_get::<bool>("", "enabled").unwrap());
        assert_eq!(
            row.try_get::<Option<String>>("", "scim_attributes")
                .unwrap(),
            None
        );

        // Reversible: the step back and forth must leave a usable schema.
        crate::migrate_database_down(&db, 1).await.unwrap();
        crate::migrate_database_up(&db, 1).await.unwrap();
    }
}
