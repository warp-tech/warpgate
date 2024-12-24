use sea_orm::Schema;
use sea_orm_migration::prelude::*;

use super::m00008_users::user as User;

pub mod api_tokens {
    use chrono::{DateTime, Utc};
    use sea_orm::entity::prelude::*;
    use sea_orm::sea_query::ForeignKeyAction;
    use serde::Serialize;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize)]
    #[sea_orm(table_name = "api_tokens")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub user_id: Uuid,
        pub label: String,
        pub secret: String,
        pub created: DateTime<Utc>,
        pub expiry: DateTime<Utc>,
    }

    #[derive(Copy, Clone, Debug, EnumIter)]
    pub enum Relation {
        User,
    }

    impl RelationTrait for Relation {
        fn def(&self) -> RelationDef {
            match self {
                Self::User => Entity::belongs_to(super::User::Entity)
                    .from(Column::UserId)
                    .to(super::User::Column::Id)
                    .on_delete(ForeignKeyAction::Cascade)
                    .into(),
            }
        }
    }

    impl Related<super::User::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::User.def()
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00014_api_tokens"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let builder = manager.get_database_backend();
        let schema = Schema::new(builder);
        manager
            .create_table(schema.create_table_from_entity(api_tokens::Entity))
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(api_tokens::Entity).to_owned())
            .await?;
        Ok(())
    }
}
