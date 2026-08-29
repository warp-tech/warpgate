use sea_orm::{ConnectionTrait, Schema};
use sea_orm_migration::prelude::*;

use crate::m00007_targets_and_roles::target;
use crate::m00010_parameters::parameters;
use crate::m00032_admin_roles::admin_role;

pub mod session_approval_request {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "session_approval_requests")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub session_id: Uuid,
        #[sea_orm(primary_key, auto_increment = false)]
        #[sea_orm(column_type = "String(StringLen::N(16))")]
        pub kind: String,
        pub node_id: Uuid,
        pub protocol: String,
        pub username: String,
        #[sea_orm(primary_key, auto_increment = false)]
        pub target: String,
        pub remote_address: Option<String>,
        pub identification_string: Option<String>,
        /// Digest of the credentials the session authenticated with; an
        /// approved row is matched against later connections through it for
        /// the grace-period bypass.
        pub credentials_digest: Option<String>,
        /// The ticket an approval of this request consumes, where consumption
        /// is deferred to the gate (HTTP ticket sessions).
        pub consumes_ticket_id: Option<Uuid>,
        pub started: OffsetDateTime,
        /// The row carries the decision itself, so an approval is resolved by
        /// writing to it from any node; the owning node reads it back.
        #[sea_orm(column_type = "String(StringLen::N(16))")]
        pub status: String,
        /// Only meaningful once approved: how widely the grant is remembered.
        #[sea_orm(column_type = "String(StringLen::N(16))", nullable)]
        pub scope: Option<String>,
        pub resolved_by_username: Option<String>,
        /// Null for a resolver that isn't a user, such as the admin API token.
        pub resolved_by_user_id: Option<Uuid>,
        /// When the question left `pending`, however it did.
        pub resolved_at: Option<OffsetDateTime>,
        /// When the owning node read the decision back and acted on it. Null
        /// while a request is still a live question.
        pub consumed_at: Option<OffsetDateTime>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(target::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("require_approval"))
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("admin_approval_timeout_seconds")).big_integer(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("admin_approval_grace_period_seconds"))
                            .big_integer(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(admin_role::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("approve_sessions"))
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;

        // Before this permission existed, holding administrator approval
        // authority was implied by being able to see sessions at all. Granting
        // it to every such role keeps existing deployments working; the column
        // defaults to off for roles created afterwards.
        let bool_true = match manager.get_database_backend() {
            sea_orm::DatabaseBackend::Postgres => "TRUE",
            _ => "1",
        };
        manager
            .get_connection()
            .execute_unprepared(&format!(
                "UPDATE admin_roles SET approve_sessions = {bool_true} WHERE sessions_view = {bool_true}"
            ))
            .await?;

        let schema = Schema::new(manager.get_database_backend());
        manager
            .create_table(schema.create_table_from_entity(session_approval_request::Entity))
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(session_approval_request::Entity)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(admin_role::Entity)
                    .drop_column(Alias::new("approve_sessions"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(target::Entity)
                    .drop_column(Alias::new("require_approval"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .drop_column(Alias::new("admin_approval_timeout_seconds"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .drop_column(Alias::new("admin_approval_grace_period_seconds"))
                    .to_owned(),
            )
            .await
    }
}
