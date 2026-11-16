use sea_orm::entity::prelude::*;
use sea_orm::{ColumnTrait, QueryFilter};
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::helpers::hash::hash_secret;

/// A bearer token an identity provider presents on the SCIM API. The secret is
/// stored as a SHA-256 digest (see `hash_secret`) and shown once at creation.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize)]
#[sea_orm(table_name = "scim_tokens")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub label: String,
    pub secret_hash: String,
    /// The SSO provider whose identity (by email) SCIM keeps in sync for
    /// provisioned users; `None` leaves SSO credentials alone.
    pub sso_provider: Option<String>,
    pub created: OffsetDateTime,
    pub expiry: Option<OffsetDateTime>,
    pub last_used: Option<OffsetDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub fn expired(&self) -> bool {
        self.expiry
            .is_some_and(|expiry| expiry <= OffsetDateTime::now_utc())
    }
}

impl Entity {
    /// The unexpired token with this secret, if any.
    pub async fn find_by_secret(
        db: &DatabaseConnection,
        secret: &str,
    ) -> Result<Option<Model>, DbErr> {
        Ok(Self::find()
            .filter(Column::SecretHash.eq(hash_secret(secret)))
            .one(db)
            .await?
            .filter(|token| !token.expired()))
    }
}
