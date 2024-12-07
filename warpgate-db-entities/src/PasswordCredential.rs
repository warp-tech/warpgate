use sea_orm::entity::prelude::*;
use sea_orm::Set;
use serde::Serialize;
use uuid::Uuid;
use warpgate_common::{UserAuthCredential, UserPasswordCredential};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize)]
#[sea_orm(table_name = "credentials_password")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub user_id: Uuid,
    pub argon_hash: String,
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

pub struct StrictModel {
    pub id: Uuid,
    pub credential: UserPasswordCredential,
}

impl From<Model> for StrictModel {
    fn from(model: Model) -> Self {
        Self {
            id: model.id,
            credential: model.clone().into(),
        }
    }
}

impl From<Model> for UserPasswordCredential {
    fn from(credential: Model) -> Self {
        UserPasswordCredential {
            hash: credential.argon_hash.to_owned().into(),
        }
    }
}

impl From<Model> for UserAuthCredential {
    fn from(model: Model) -> Self {
        Self::Password(model.into())
    }
}

impl From<UserPasswordCredential> for ActiveModel {
    fn from(credential: UserPasswordCredential) -> Self {
        Self {
            argon_hash: Set(credential.hash.expose_secret().into()),
            ..Default::default()
        }
    }
}
