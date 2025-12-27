use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;
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
    pub timestamp: DateTime<Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        panic!("No relations defined")
    }
}

impl ActiveModelBehavior for ActiveModel {}
