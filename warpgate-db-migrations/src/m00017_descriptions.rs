use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00017_descriptions"
    }
}

use crate::m00007_targets_and_roles::target;
use crate::m00008_users::user;

pub mod role {
    use sea_orm::entity::prelude::*;
    use serde::Serialize;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize)]
    #[sea_orm(table_name = "roles")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub name: String,
        #[sea_orm(column_type = "Text")]
        pub description: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(user::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("description"))
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(role::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("description"))
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(target::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("description"))
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .to_owned(),
            )
            .await?;

        // set description for builtin admin role
        if let Some(admin_role) = role::Entity::find()
            .filter(role::Column::Name.eq("warpgate:admin"))
            .one(manager.get_connection())
            .await?
        {
            role::ActiveModel {
                id: Set(admin_role.id),
                description: Set("Built-in admin role".into()),
                name: Set(admin_role.name),
            }
            .update(manager.get_connection())
            .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(target::Entity)
                    .drop_column(Alias::new("description"))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(user::Entity)
                    .drop_column(Alias::new("description"))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(role::Entity)
                    .drop_column(Alias::new("description"))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
