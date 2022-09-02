use sea_orm::Schema;
use sea_orm_migration::prelude::*;

mod user {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "users")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub username: String,
        pub credentials: serde_json::Value,
        pub credential_policy: serde_json::Value,
    }

    impl Related<crate::m00007_targets_and_roles::role::Entity> for Entity {
        fn to() -> RelationDef {
            super::user_role_assignment::Relation::User.def()
        }

        fn via() -> Option<RelationDef> {
            Some(super::user_role_assignment::Relation::Role.def().rev())
        }
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

mod user_role_assignment {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "user_roles")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: u32,
        pub user_id: Uuid,
        pub role_id: Uuid,
    }

    #[derive(Copy, Clone, Debug, EnumIter)]
    pub enum Relation {
        User,
        Role,
    }

    impl RelationTrait for Relation {
        fn def(&self) -> RelationDef {
            match self {
                Self::User => Entity::belongs_to(super::user::Entity)
                    .from(Column::UserId)
                    .to(super::user::Column::Id)
                    .into(),
                Self::Role => Entity::belongs_to(crate::m00007_targets_and_roles::role::Entity)
                    .from(Column::RoleId)
                    .to(crate::m00007_targets_and_roles::role::Column::Id)
                    .into(),
            }
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00008_users"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let builder = manager.get_database_backend();
        let schema = Schema::new(builder);
        manager
            .create_table(schema.create_table_from_entity(user::Entity))
            .await?;
        manager
            .create_table(schema.create_table_from_entity(user_role_assignment::Entity))
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(user_role_assignment::Entity).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(user::Entity).to_owned())
            .await?;
        Ok(())
    }
}
