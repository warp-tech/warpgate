use sea_orm::Schema;
use sea_orm_migration::prelude::*;

pub mod parameters {
    use sea_orm::entity::prelude::*;
    use sea_orm::Set;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "parameters")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub allow_own_credential_management: bool,
    }

    impl ActiveModelBehavior for ActiveModel {}

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl Model {
        pub async fn get(db: &DatabaseConnection) -> Result<Self, DbErr> {
            match Entity::find().one(db).await? {
                Some(model) => Ok(model),
                None => {
                    ActiveModel {
                        id: Set(Uuid::new_v4()),
                        allow_own_credential_management: Set(true),
                    }
                    .insert(db)
                    .await
                }
            }
        }
    }
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00010_parameters"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let builder = manager.get_database_backend();
        let schema = Schema::new(builder);
        manager
            .create_table(schema.create_table_from_entity(parameters::Entity))
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(parameters::Entity).to_owned())
            .await?;
        Ok(())
    }
}
