use poem_openapi::Object;
use sea_orm::entity::prelude::*;
use serde::Serialize;
use uuid::Uuid;
use warpgate_common::{User, UserAuthCredential, UserRequireCredentialsPolicy};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "users")]
#[oai(rename = "User")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub username: String,
    pub credentials: serde_json::Value,
    pub credential_policy: serde_json::Value,
}

impl Related<super::Role::Entity> for Entity {
    fn to() -> RelationDef {
        super::UserRoleAssignment::Relation::Role.def()
    }

    fn via() -> Option<RelationDef> {
        Some(super::UserRoleAssignment::Relation::User.def().rev())
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl TryFrom<Model> for User {
    type Error = serde_json::Error;

    fn try_from(model: Model) -> Result<Self, Self::Error> {
        let credentials: Vec<UserAuthCredential> = serde_json::from_value(model.credentials)?;
        let credential_policy: Option<UserRequireCredentialsPolicy> =
            serde_json::from_value(model.credential_policy)?;
        Ok(Self {
            id: model.id,
            username: model.username,
            roles: vec![],
            credentials,
            credential_policy,
        })
    }
}
