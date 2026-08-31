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

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::ActiveValue::Set;
    use sea_orm::{Database, EntityTrait};
    use sea_orm_migration::MigratorTrait;
    use time::OffsetDateTime;
    use uuid::Uuid;
    use warpgate_common::TargetSessionId;
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
    use warpgate_db_entities::{SessionCommand, TargetSession};

    use crate::Migrator;

    #[tokio::test]
    async fn up_down_up_round_trip() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();

        let target_session_id = TargetSessionId(Uuid::new_v4());
        TargetSession::Entity::insert(TargetSession::ActiveModel {
            id: Set(target_session_id),
            user_session_id: Set(warpgate_common::UserSessionId(Uuid::new_v4())),
            target_snapshot: Set(r#"{"name":"web"}"#.into()),
            target_id: Set(Uuid::new_v4()),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            ticket_id: Set(None),
            node_id: Set(None),
        })
        .exec_without_returning(&db)
        .await
        .unwrap();
        SessionCommand::Entity::insert(SessionCommand::ActiveModel {
            id: Set(Uuid::new_v4()),
            target_session_id: Set(target_session_id),
            command: Set("ls".into()),
            time: Set(OffsetDateTime::now_utc()),
            node_id: Set(None),
        })
        .exec_without_returning(&db)
        .await
        .unwrap();
        assert_eq!(
            SessionCommand::Entity::find().all(&db).await.unwrap().len(),
            1
        );

        Migrator::down(&db, Some(1)).await.unwrap();
        // Down must leave no trace — re-running up rebuilds the table empty.
        Migrator::up(&db, Some(1)).await.unwrap();
        assert_eq!(
            SessionCommand::Entity::find().all(&db).await.unwrap().len(),
            0
        );
    }
}
