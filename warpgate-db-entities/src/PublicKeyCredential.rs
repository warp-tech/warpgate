use sea_orm::entity::prelude::*;
use sea_orm::Set;
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

impl From<Model> for UserPublicKeyCredential {
    fn from(credential: Model) -> Self {
        UserPublicKeyCredential {
            key: credential.openssh_public_key.into(),
        }
    }
}

impl From<Model> for UserAuthCredential {
    fn from(model: Model) -> Self {
        Self::PublicKey(model.into())
    }
}

impl From<UserPublicKeyCredential> for ActiveModel {
    fn from(credential: UserPublicKeyCredential) -> Self {
        Self {
            openssh_public_key: Set(credential.key.expose_secret().clone()),
            ..Default::default()
        }
    }
}
