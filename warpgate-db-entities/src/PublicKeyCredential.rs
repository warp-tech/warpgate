use sea_orm::entity::prelude::*;
use serde::Serialize;
use uuid::Uuid;
use warpgate_common::{UserAuthCredential, UserPublicKeyCredential};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize)]
#[sea_orm(table_name = "credentials_public_key")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub user_id: Uuid,
    pub openssh_public_key: String,
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

impl From<Model> for UserAuthCredential {
    fn from(credential: Model) -> Self {
        Self::PublicKey(UserPublicKeyCredential {
            key: credential.openssh_public_key.into(),
        })
    }
}
