use sea_orm::entity::prelude::*;
use sea_orm::sea_query::{Func, IntoCondition};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "failed_login_attempts")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,

    /// Username that was attempted (may not exist)
    pub username: String,

    /// Remote IP address of the client
    pub remote_ip: String,

    /// Protocol used: "ssh", "http", "mysql", "postgres"
    pub protocol: String,

    /// Credential type attempted: "password", "otp", "publickey"
    pub credential_type: String,

    /// When the attempt occurred
    pub timestamp: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Entity {
    /// Usernames are case-insensitive; count attempts against an account the
    /// same way authentication resolves it, so the per-user lockout threshold
    /// can't be sidestepped by rotating the case of the username.
    pub fn username_eq_ci(username: &str) -> impl IntoCondition {
        Expr::expr(Func::lower(Expr::col(Column::Username))).eq(username.to_lowercase())
    }
}
