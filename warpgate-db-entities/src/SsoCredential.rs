use sea_orm::entity::prelude::*;
use sea_orm::sea_query::ForeignKeyAction;
use sea_orm::Set;
use serde::Serialize;
use uuid::Uuid;
use warpgate_common::{UserAuthCredential, UserSsoCredential};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize)]
#[sea_orm(table_name = "credentials_sso")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider: Option<String>,
    pub email: String,
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

impl From<Model> for UserSsoCredential {
    fn from(credential: Model) -> Self {
        UserSsoCredential {
            provider: credential.provider,
            email: credential.email,
        }
    }
}

impl From<Model> for UserAuthCredential {
    fn from(model: Model) -> Self {
        Self::Sso(model.into())
    }
}

impl From<UserSsoCredential> for ActiveModel {
    fn from(credential: UserSsoCredential) -> Self {
        Self {
            provider: Set(credential.provider),
            email: Set(credential.email),
            ..Default::default()
        }
    }
}
