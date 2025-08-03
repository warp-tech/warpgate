use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;
use sea_orm::sea_query::ForeignKeyAction;
use sea_orm::Set;
use serde::Serialize;
use uuid::Uuid;
use warpgate_common::{UserAuthCredential, UserCertificateCredential};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize)]
#[sea_orm(table_name = "credentials_certificate")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub user_id: Uuid,
    pub label: String,
    pub date_added: Option<DateTime<Utc>>,
    pub last_used: Option<DateTime<Utc>>,
    #[sea_orm(column_type = "Text")]
    pub certificate: String,
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

impl From<Model> for UserCertificateCredential {
    fn from(credential: Model) -> Self {
        UserCertificateCredential {
            certificate: credential.certificate.into(),
        }
    }
}

impl From<Model> for UserAuthCredential {
    fn from(model: Model) -> Self {
        Self::Certificate(model.into())
    }
}

impl From<UserCertificateCredential> for ActiveModel {
    fn from(credential: UserCertificateCredential) -> Self {
        Self {
            certificate: Set(credential.certificate.expose_secret().clone()),
            ..Default::default()
        }
    }
}
