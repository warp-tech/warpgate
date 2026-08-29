use sea_orm::{ConnectionTrait, Schema, TransactionTrait};
use sea_orm_migration::prelude::*;

/// An approval request is about one session reaching one target, but the table
/// was keyed on the session and the kind alone — so a session that reached a
/// second gated target had nowhere to put the new question and took the old
/// row over, discarding the answer already recorded there. The target joins the
/// key, and the two questions become two rows.
#[derive(DeriveMigrationName)]
pub struct Migration;

const TABLE: &str = "session_approval_requests";
const TMP: &str = "session_approval_requests_new_pk";

/// The table as it is becoming: identical to the live entity except that the
/// target is part of the primary key.
mod rekeyed {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "session_approval_requests_new_pk")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub session_id: Uuid,
        #[sea_orm(primary_key, auto_increment = false)]
        #[sea_orm(column_type = "String(StringLen::N(16))")]
        pub kind: String,
        #[sea_orm(primary_key, auto_increment = false)]
        pub target: String,
        pub node_id: Uuid,
        pub protocol: String,
        pub username: String,
        pub remote_address: Option<String>,
        pub identification_string: Option<String>,
        pub credentials_digest: Option<String>,
        pub consumes_ticket_id: Option<Uuid>,
        pub started: OffsetDateTime,
        #[sea_orm(column_type = "String(StringLen::N(16))")]
        pub status: String,
        #[sea_orm(column_type = "String(StringLen::N(16))", nullable)]
        pub scope: Option<String>,
        pub resolved_by_username: Option<String>,
        pub resolved_by_user_id: Option<Uuid>,
        pub resolved_at: Option<OffsetDateTime>,
        pub consumed_at: Option<OffsetDateTime>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// Every column, in one order, for the copy across.
const COLUMNS: &str = "session_id, kind, target, node_id, protocol, username, \
     remote_address, identification_string, credentials_digest, \
     consumes_ticket_id, started, status, scope, resolved_by_username, \
     resolved_by_user_id, resolved_at, consumed_at";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // sea-orm only wraps a migration in a transaction on PostgreSQL; left
        // to itself on SQLite the statements land on different pooled
        // connections, one of which still holds the older schema.
        let db = manager.get_connection().begin().await?;
        let backend = db.get_database_backend();

        let schema = Schema::new(backend);
        db.execute(backend.build(&schema.create_table_from_entity(rekeyed::Entity)))
            .await?;

        // The old key implies the new one, so every row carries across as it
        // stands — there is nothing to deduplicate.
        db.execute_unprepared(&format!(
            "INSERT INTO {TMP} ({COLUMNS}) SELECT {COLUMNS} FROM {TABLE}"
        ))
        .await?;

        db.execute(backend.build(&Table::drop().table(Alias::new(TABLE)).to_owned()))
            .await?;
        db.execute(
            backend.build(
                &Table::rename()
                    .table(Alias::new(TMP), Alias::new(TABLE))
                    .to_owned(),
            ),
        )
        .await?;

        db.commit().await
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // Narrowing the key back would have to choose which of a session's
        // questions to keep, and there is no answer to that which isn't a
        // guess.
        Err(DbErr::Migration(
            "cannot narrow the approval request key without discarding requests".to_owned(),
        ))
    }
}
