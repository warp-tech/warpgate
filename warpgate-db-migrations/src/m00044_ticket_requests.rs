use sea_orm::Schema;
use sea_orm_migration::prelude::*;

use crate::m00001_create_ticket::ticket;
use crate::m00007_targets_and_roles::target;
use crate::m00010_parameters::parameters;
use crate::m00032_admin_roles::admin_role;

pub mod user {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "users")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub username: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod ticket_request {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "ticket_requests")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub user_id: Uuid,
        pub target_id: Uuid,
        pub requested_duration_seconds: Option<i64>,
        #[sea_orm(column_type = "Text")]
        pub description: String,
        #[sea_orm(column_type = "String(StringLen::N(16))")]
        pub status: String,
        pub resolved_by_user_id: Option<Uuid>,
        pub ticket_id: Option<Uuid>,
        pub created: OffsetDateTime,
        pub resolved_at: Option<OffsetDateTime>,
        #[sea_orm(column_type = "Text", nullable)]
        pub deny_reason: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "super::user::Entity",
            from = "Column::UserId",
            to = "super::user::Column::Id"
        )]
        User,
        #[sea_orm(
            belongs_to = "crate::m00007_targets_and_roles::target::Entity",
            from = "Column::TargetId",
            to = "crate::m00007_targets_and_roles::target::Column::Id"
        )]
        Target,
        #[sea_orm(
            belongs_to = "crate::m00001_create_ticket::ticket::Entity",
            from = "Column::TicketId",
            to = "crate::m00001_create_ticket::ticket::Column::Id"
        )]
        Ticket,
    }

    impl ActiveModelBehavior for ActiveModel {}
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00044_ticket_requests"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let builder = manager.get_database_backend();
        let schema = Schema::new(builder);

        manager
            .create_table(schema.create_table_from_entity(ticket_request::Entity))
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(ticket::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("self_service"))
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
                    .table(admin_role::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("ticket_requests_manage"))
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
                        ColumnDef::new(Alias::new("ticket_self_service_enabled"))
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
                        ColumnDef::new(Alias::new("ticket_auto_approve_existing_access"))
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("ticket_max_duration_seconds"))
                            .big_integer()
                            .null()
                            .default(28800i64),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("ticket_max_uses"))
                            .small_integer()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(parameters::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("ticket_require_description"))
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
                        ColumnDef::new(Alias::new("ticket_request_show_all_targets"))
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
                    .table(target::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("ticket_max_duration_seconds"))
                            .big_integer()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(target::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("ticket_requests_disabled"))
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
                    .table(target::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("ticket_require_approval"))
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
                    .table(target::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("ticket_max_uses"))
                            .small_integer()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        let conn = manager.get_connection();
        let bool_true = match manager.get_database_backend() {
            sea_orm::DatabaseBackend::Postgres => "TRUE",
            _ => "1",
        };
        conn.execute_unprepared(&format!(
            "UPDATE admin_roles SET ticket_requests_manage = {bool_true} WHERE name = 'warpgate:admin'",
        ))
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ticket_request::Entity).to_owned())
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("tickets"))
                    .drop_column(Alias::new("self_service"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("admin_roles"))
                    .drop_column(Alias::new("ticket_requests_manage"))
                    .to_owned(),
            )
            .await?;

        for col in [
            "ticket_self_service_enabled",
            "ticket_auto_approve_existing_access",
            "ticket_max_duration_seconds",
            "ticket_max_uses",
            "ticket_require_description",
            "ticket_request_show_all_targets",
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("parameters"))
                        .drop_column(Alias::new(col))
                        .to_owned(),
                )
                .await?;
        }

        for col in [
            "ticket_max_duration_seconds",
            "ticket_requests_disabled",
            "ticket_require_approval",
            "ticket_max_uses",
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("targets"))
                        .drop_column(Alias::new(col))
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }
}
