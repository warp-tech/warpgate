use sea_orm::entity::prelude::*;
use sea_orm::sea_query::ForeignKeyAction;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::UserAuthCredential;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize)]
#[sea_orm(table_name = "credentials_webauthn")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub user_id: Uuid,
    pub label: String,
    /// The credential ID from webauthn-rs, stored as base64
    #[sea_orm(column_type = "Text")]
    pub credential_id: String,
    /// The full SecurityKey serialized as JSON (public key + metadata; no secret)
    #[sea_orm(column_type = "Text")]
    pub credential_json: String,
    pub date_added: Option<OffsetDateTime>,
    pub last_used: Option<OffsetDateTime>,
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

impl From<Model> for UserAuthCredential {
    fn from(model: Model) -> Self {
        Self::WebAuthn(warpgate_common::UserWebAuthnCredential {
            credential_id: model.credential_id,
            credential_json: model.credential_json,
            label: model.label,
        })
    }
}
