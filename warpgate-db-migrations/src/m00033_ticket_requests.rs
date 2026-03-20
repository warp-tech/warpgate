use sea_orm::Schema;
use sea_orm_migration::prelude::*;

pub(crate) mod ticket_request {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "ticket_requests")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub user_id: Uuid,
        pub username: String,
        pub target_name: String,
        pub requested_duration_seconds: Option<i64>,
        pub requested_uses: Option<i16>,
        #[sea_orm(column_type = "Text")]
        pub description: String,
        #[sea_orm(column_type = "String(StringLen::N(16))")]
        pub status: String,
        pub resolved_by_username: Option<String>,
        pub ticket_id: Option<Uuid>,
        pub created: DateTimeUtc,
        pub resolved_at: Option<DateTimeUtc>,
        #[sea_orm(column_type = "Text", nullable)]
        pub deny_reason: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00033_ticket_requests"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let builder = manager.get_database_backend();
        let schema = Schema::new(builder);

        // Create ticket_requests table
        manager
            .create_table(schema.create_table_from_entity(ticket_request::Entity))
            .await?;

        // Add self_service column to tickets table
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("tickets"))
                    .add_column(
                        ColumnDef::new(Alias::new("self_service"))
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;

        // Add ticket_requests_manage column to admin_roles table
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("admin_roles"))
                    .add_column(
                        ColumnDef::new(Alias::new("ticket_requests_manage"))
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;

        // Add ticket policy columns to parameters table
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("parameters"))
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
                    .table(Alias::new("parameters"))
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
                    .table(Alias::new("parameters"))
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
                    .table(Alias::new("parameters"))
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
                    .table(Alias::new("parameters"))
                    .add_column(
                        ColumnDef::new(Alias::new("ticket_require_description"))
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;

        // Add per-target ticket max duration
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("targets"))
                    .add_column(
                        ColumnDef::new(Alias::new("ticket_max_duration_seconds"))
                            .big_integer()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Grant ticket_requests_manage to the built-in warpgate:admin role
        let conn = manager.get_connection();
        let bool_true = match manager.get_database_backend() {
            sea_orm::DatabaseBackend::Postgres => "TRUE",
            _ => "1",
        };
        conn.execute_unprepared(&format!(
            "UPDATE admin_roles SET ticket_requests_manage = {} WHERE name = 'warpgate:admin'",
            bool_true
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

        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("targets"))
                    .drop_column(Alias::new("ticket_max_duration_seconds"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
