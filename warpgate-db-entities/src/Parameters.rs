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

impl Entity {
    pub async fn get(db: &DatabaseConnection) -> Result<Model, DbErr> {
        match Self::find().one(db).await? {
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
