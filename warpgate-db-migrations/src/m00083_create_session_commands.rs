use sea_orm::Schema;
use sea_orm_migration::prelude::*;

pub mod session_command {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    use crate::m00083_create_session_commands::target_session;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "session_commands")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub target_session_id: Uuid,
        #[sea_orm(column_type = "Text")]
        pub command: String,
        pub time: OffsetDateTime,
        pub node_id: Option<Uuid>,
    }

    #[derive(Copy, Clone, Debug, EnumIter)]
    pub enum Relation {
        TargetSession,
    }

    impl RelationTrait for Relation {
        fn def(&self) -> RelationDef {
            match self {
                Self::TargetSession => Entity::belongs_to(target_session::Entity)
                    .from(Column::TargetSessionId)
                    .to(target_session::Column::Id)
                    .on_delete(ForeignKeyAction::Cascade)
                    .into(),
            }
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}

/// Stand-in for the target sessions table (created as `sessions` in m00002,
/// renamed in m00082) so the FK can reference it by its current name.
pub mod target_session {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "target_sessions")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
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
        let builder = manager.get_database_backend();
        let schema = Schema::new(builder);

        manager
            .create_table(schema.create_table_from_entity(session_command::Entity))
            .await?;

        // The parent-session join (search results link back to their session)
        // and the cascade delete both key on the target session.
        manager
            .create_index(
                Index::create()
                    .table(session_command::Entity)
                    .name("idx_session_commands__target_session_id")
                    .col(session_command::Column::TargetSessionId)
                    .to_owned(),
            )
            .await?;
        // Results are ordered by time, newest first.
        manager
            .create_index(
                Index::create()
                    .table(session_command::Entity)
                    .name("idx_session_commands__time")
                    .col(session_command::Column::Time)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(session_command::Entity).to_owned())
            .await
    }
}
