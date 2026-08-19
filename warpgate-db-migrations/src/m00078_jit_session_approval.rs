use sea_orm::Schema;
use sea_orm_migration::prelude::*;

use crate::m00007_targets_and_roles::target;
use crate::m00010_parameters::parameters;

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
        pub auth_state_id: Option<Uuid>,
        pub node_id: Uuid,
        pub protocol: String,
        pub username: String,
        pub target: String,
        pub remote_address: Option<String>,
        pub identification_string: Option<String>,
        pub started: OffsetDateTime,
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
