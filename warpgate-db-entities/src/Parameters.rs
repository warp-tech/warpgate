use sea_orm::entity::prelude::*;
use sea_orm::Set;
use uuid::Uuid;
use warpgate_common::PasswordPolicy;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "parameters")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub allow_own_credential_management: bool,
    pub rate_limit_bytes_per_second: Option<i64>,
    #[sea_orm(column_type = "Text")]
    pub ca_certificate_pem: String,
    #[sea_orm(column_type = "Text")]
    pub ca_private_key_pem: String,
    pub ssh_client_auth_publickey: bool,
    pub ssh_client_auth_password: bool,
    pub ssh_client_auth_keyboard_interactive: bool,
    pub minimize_password_login: bool,
    pub show_session_menu: bool,
    pub password_policy_min_length: i32,
    pub password_policy_require_uppercase: bool,
    pub password_policy_require_lowercase: bool,
    pub password_policy_require_digits: bool,
    pub password_policy_require_special: bool,
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl Model {
    pub fn password_policy(&self) -> PasswordPolicy {
        PasswordPolicy {
            min_length: self.password_policy_min_length.max(0) as u32,
            require_uppercase: self.password_policy_require_uppercase,
            require_lowercase: self.password_policy_require_lowercase,
            require_digits: self.password_policy_require_digits,
            require_special: self.password_policy_require_special,
        }
    }
}

impl Entity {
    pub async fn get(db: &DatabaseConnection) -> Result<Model, DbErr> {
        match Self::find().one(db).await? {
            Some(model) => Ok(model),
            None => {
                ActiveModel {
                    id: Set(Uuid::new_v4()),
                    allow_own_credential_management: Set(true),
                    rate_limit_bytes_per_second: Set(None),
                    ca_certificate_pem: Set("".into()),
                    ca_private_key_pem: Set("".into()),
                    ssh_client_auth_publickey: Set(true),
                    ssh_client_auth_password: Set(true),
                    ssh_client_auth_keyboard_interactive: Set(true),
                    minimize_password_login: Set(false),
                    show_session_menu: Set(true),
                    password_policy_min_length: Set(0),
                    password_policy_require_uppercase: Set(false),
                    password_policy_require_lowercase: Set(false),
                    password_policy_require_digits: Set(false),
                    password_policy_require_special: Set(false),
                }
                .insert(db)
                .await
            }
        }
    }
}
