use sea_orm::entity::prelude::*;
use sea_orm::sea_query::ForeignKeyAction;
use serde::Serialize;
use uuid::Uuid;

/// A per-user Oracle 12c O5LOGON verifier (the `warpgate-oracle-tns::Verifier12c`
/// material), stored hex-encoded. It is not the plaintext password, but it is
/// password-equivalent for O5LOGON and far cheaper to brute-force than the
/// Argon2 hash, so it is only kept while the Oracle listener is enabled (see
/// `warpgate_core::oracle_verifier`).
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize)]
#[sea_orm(table_name = "credentials_oracle")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub user_id: Uuid,
    /// `AUTH_VFR_DATA` salt (16 bytes, hex).
    pub vfr_data: String,
    /// `AUTH_PBKDF2_VGEN_COUNT` password-key iterations.
    pub vgen_count: i32,
    /// `AUTH_PBKDF2_CSK_SALT` combo-key salt (16 bytes, hex).
    pub csk_salt: String,
    /// `AUTH_PBKDF2_SDER_COUNT` combo-key iterations.
    pub sder_count: i32,
    /// The 64-byte stretched password key (hex); not reversible to the password.
    pub password_key: String,
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
