use poem_openapi::Enum;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::Serialize;
use uuid::Uuid;
use warpgate_common::PasswordPolicy;

#[derive(Debug, PartialEq, Eq, Serialize, Clone, Copy, Enum, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(32))")]
pub enum TargetClickAction {
    #[sea_orm(string_value = "Connect")]
    Connect,
    #[sea_orm(string_value = "ShowInstructions")]
    ShowInstructions,
}

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
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
    pub ticket_self_service_enabled: bool,
    pub ticket_auto_approve_existing_access: bool,
    pub ticket_max_duration_seconds: Option<i64>,
    pub ticket_max_uses: Option<i16>,
    pub ticket_require_description: bool,
    pub ticket_request_show_all_targets: bool,
    pub target_click_action: TargetClickAction,
    pub show_session_menu: bool,
    pub password_policy_min_length: i32,
    pub password_policy_require_uppercase: bool,
    pub password_policy_require_lowercase: bool,
    pub password_policy_require_digits: bool,
    pub password_policy_require_special: bool,
    pub max_api_token_duration_seconds: Option<i64>,
    pub record_scp: bool,
    pub tutorial_dismissed: bool,
    pub login_protection_enabled: bool,
    pub login_protection_retention_seconds: i32,
    pub lp_ip_max_attempts: i32,
    pub lp_ip_time_window_seconds: i32,
    pub lp_ip_base_block_duration_seconds: i32,
    pub lp_ip_block_duration_multiplier: f64,
    pub lp_ip_max_block_duration_seconds: i32,
    pub lp_ip_cooldown_reset_seconds: i32,
    pub lp_user_max_attempts: i32,
    pub lp_user_time_window_seconds: i32,
    pub lp_user_auto_unlock: bool,
    pub lp_user_lockout_duration_seconds: i32,
    pub lp_user_exempt_admins: bool,
    pub web_ssh_enabled: bool,
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
                    ticket_self_service_enabled: Set(false),
                    ticket_auto_approve_existing_access: Set(true),
                    ticket_max_duration_seconds: Set(Some(28800)),
                    ticket_max_uses: Set(None),
                    ticket_require_description: Set(false),
                    ticket_request_show_all_targets: Set(false),
                    target_click_action: Set(TargetClickAction::Connect),
                    show_session_menu: Set(true),
                    password_policy_min_length: Set(0),
                    password_policy_require_uppercase: Set(false),
                    password_policy_require_lowercase: Set(false),
                    password_policy_require_digits: Set(false),
                    password_policy_require_special: Set(false),
                    max_api_token_duration_seconds: Set(None),
                    record_scp: Set(true),
                    tutorial_dismissed: Set(false),
                    login_protection_enabled: Set(true),
                    login_protection_retention_seconds: Set(2592000),
                    lp_ip_max_attempts: Set(5),
                    lp_ip_time_window_seconds: Set(900),
                    lp_ip_base_block_duration_seconds: Set(1800),
                    lp_ip_block_duration_multiplier: Set(2.0),
                    lp_ip_max_block_duration_seconds: Set(86400),
                    lp_ip_cooldown_reset_seconds: Set(86400),
                    lp_user_max_attempts: Set(10),
                    lp_user_time_window_seconds: Set(3600),
                    lp_user_auto_unlock: Set(true),
                    lp_user_lockout_duration_seconds: Set(3600),
                    lp_user_exempt_admins: Set(true),
                    web_ssh_enabled: Set(true),
                }
                .insert(db)
                .await
            }
        }
    }
}
