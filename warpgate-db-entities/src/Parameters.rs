use std::collections::HashMap;

use poem_openapi::{Enum, Object, Union};
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_aws::S3StorageConfig;
use warpgate_common::auth::CredentialKind;
use warpgate_common::{PasswordPolicy, Protocol, UserAuthCredential, UserRequireCredentialsPolicy};

#[derive(Debug, PartialEq, Eq, Serialize, Clone, Copy, Enum, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(32))")]
pub enum TargetClickAction {
    #[sea_orm(string_value = "Connect")]
    Connect,
    #[sea_orm(string_value = "ShowInstructions")]
    ShowInstructions,
}

/// How the portal decides whether targets open in a new browser tab.
#[derive(Debug, PartialEq, Eq, Serialize, Clone, Copy, Enum, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(32))")]
pub enum OpenTargetsInNewTabMode {
    /// Use a new tab by default, but allow each browser to override it.
    #[sea_orm(string_value = "DefaultOn")]
    DefaultOn,
    /// Use the current tab by default, but allow each browser to override it.
    #[sea_orm(string_value = "DefaultOff")]
    DefaultOff,
    /// Always use a new tab and don't allow browser overrides.
    #[sea_orm(string_value = "ForcedOn")]
    ForcedOn,
    /// Always use the current tab and don't allow browser overrides.
    #[sea_orm(string_value = "ForcedOff")]
    ForcedOff,
}

/// How the password login form is presented on the gateway login page.
#[derive(Debug, PartialEq, Eq, Serialize, Clone, Copy, Enum, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(32))")]
pub enum PasswordLoginMode {
    /// Password form shown alongside other methods.
    #[sea_orm(string_value = "Enabled")]
    Enabled,
    /// Password form hidden behind a "Password login" link.
    #[sea_orm(string_value = "Minimized")]
    Minimized,
    /// Password login not offered and rejected by the server.
    #[sea_orm(string_value = "Disabled")]
    Disabled,
}

#[derive(
    Debug, Default, PartialEq, Eq, Serialize, Clone, Copy, Enum, EnumIter, DeriveActiveEnum,
)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(32))")]
pub enum MfaEnforcement {
    #[default]
    #[sea_orm(string_value = "Off")]
    Off,
    /// Web users without TOTP get enrolled, other protocols do not require it
    #[sea_orm(string_value = "Enroll")]
    Enroll,
    /// Above + all protocols require MFA
    #[sea_orm(string_value = "Require")]
    Require,
}

/// What to do when a target's SSH host key isn't in the known hosts list.
#[derive(
    Debug, Default, PartialEq, Eq, Serialize, Clone, Copy, Enum, EnumIter, DeriveActiveEnum,
)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(32))")]
pub enum SshHostKeyVerificationMode {
    /// Ask the user to trust the key, then remember it.
    #[default]
    #[sea_orm(string_value = "Prompt")]
    Prompt,
    /// Trust and remember the key without asking.
    #[sea_orm(string_value = "AutoAccept")]
    AutoAccept,
    /// Refuse to connect to hosts with unknown keys.
    #[sea_orm(string_value = "AutoReject")]
    AutoReject,
    /// Don't check or remember host keys at all - no protection against MITM,
    /// but tolerates hosts that rotate their keys.
    #[sea_orm(string_value = "Ignore")]
    Ignore,
}

impl From<warpgate_common::SshHostKeyVerificationMode> for SshHostKeyVerificationMode {
    fn from(mode: warpgate_common::SshHostKeyVerificationMode) -> Self {
        use warpgate_common::SshHostKeyVerificationMode as C;
        match mode {
            C::Prompt => Self::Prompt,
            C::AutoAccept => Self::AutoAccept,
            C::AutoReject => Self::AutoReject,
            C::Ignore => Self::Ignore,
        }
    }
}

/// Whether the instance reports anonymous usage analytics, and at which
/// payload level. `Undecided` triggers the one-time opt-in prompt in the admin
/// UI; the instance never reports until the choice is made.
#[derive(Debug, PartialEq, Eq, Serialize, Clone, Copy, Enum, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(32))")]
pub enum AnalyticsConsent {
    /// No choice made yet — prompt the admin and report nothing.
    #[sea_orm(string_value = "Undecided")]
    Undecided,
    /// Analytics disabled.
    #[sea_orm(string_value = "Off")]
    Off,
    /// Analytics enabled.
    #[sea_orm(string_value = "On")]
    On,
}

/// Where session recordings are stored, and everything that backend needs.
/// Serves as both the stored (serde) and admin-API (poem-openapi)
/// representation, so only valid field combinations can exist (e.g. no S3
/// settings while on disk).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Union)]
#[serde(tag = "kind")]
#[oai(discriminator_name = "kind", one_of)]
pub enum RecordingsStorageConfig {
    Disk(RecordingsDiskConfig),
    S3(S3StorageConfig),
}

impl Default for RecordingsStorageConfig {
    fn default() -> Self {
        Self::Disk(RecordingsDiskConfig {
            path: "./data/recordings".into(),
        })
    }
}

/// The config-file settings that have since moved into the parameters row,
/// published by the process before migrations run so that the migrations can
/// copy them into the row of an existing install.
#[derive(Default)]
pub struct ConfigMigrationValues {
    pub recordings_enable: bool,
    pub recordings_path: String,
    pub ssh_host_key_verification: SshHostKeyVerificationMode,
}

impl ConfigMigrationValues {
    pub fn from_config(config: &warpgate_common::WarpgateConfig) -> Self {
        let recordings = config.store.recordings.clone().unwrap_or_default();
        Self {
            recordings_enable: recordings.enable,
            recordings_path: recordings.path,
            ssh_host_key_verification: config.store.ssh.host_key_verification.into(),
        }
    }
}

static CONFIG_MIGRATION_VALUES: std::sync::OnceLock<ConfigMigrationValues> =
    std::sync::OnceLock::new();

pub fn set_config_migration_values(values: ConfigMigrationValues) {
    let _ = CONFIG_MIGRATION_VALUES.set(values);
}

pub fn get_config_migration_values() -> &'static ConfigMigrationValues {
    #[allow(clippy::expect_used, reason = "must be set before migrations run")]
    CONFIG_MIGRATION_VALUES
        .get()
        .expect("recordings migration values must be set before migrations run")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Object)]
pub struct RecordingsDiskConfig {
    pub path: String,
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
    pub ssh_host_key_verification: SshHostKeyVerificationMode,
    pub password_login_mode: PasswordLoginMode,
    pub mfa_enforcement: MfaEnforcement,
    pub mfa_policy_exempt_sso_users: bool,
    pub ticket_self_service_enabled: bool,
    pub ticket_auto_approve_existing_access: bool,
    pub ticket_max_duration_seconds: Option<i64>,
    pub ticket_max_uses: Option<i16>,
    pub ticket_require_description: bool,
    pub ticket_request_show_all_targets: bool,
    pub target_click_action: TargetClickAction,
    pub open_targets_in_new_tab: OpenTargetsInNewTabMode,
    pub show_session_menu: bool,
    pub password_policy_min_length: i32,
    pub password_policy_require_uppercase: bool,
    pub password_policy_require_lowercase: bool,
    pub password_policy_require_digits: bool,
    pub password_policy_require_special: bool,
    pub max_api_token_duration_seconds: Option<i64>,
    pub record_scp: bool,
    /// Whether keystrokes are kept in desktop session recordings.
    pub record_desktop_keyboard_input: bool,
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
    #[sea_orm(column_type = "Text")]
    pub banner: String,
    pub web_clients_enabled: bool,
    pub analytics_consent: AnalyticsConsent,
    pub analytics_normal: bool,
    pub analytics_instance_id: String,
    pub instance_created_at: OffsetDateTime,
    pub web_auth_max_age_seconds: Option<i64>,
    pub web_approval_grace_period_seconds: Option<i64>,
    pub recordings_enable: bool,
    /// Serialized [`RecordingsStorageConfig`].
    #[sea_orm(column_type = "Text")]
    pub recordings_storage: String,
    /// Serialized [`UserRequireCredentialsPolicy`]
    #[sea_orm(column_type = "Text")]
    pub default_credential_policy: String,

    /// Shared secret authenticating cross-node recording proxying. Generated by
    /// the first node to boot; never exposed through the admin API.
    #[sea_orm(column_type = "Text", nullable)]
    pub cluster_token: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub encryption_key_fp: Option<String>,
    /// Fingerprint of the previous key while a rotation is going on
    #[sea_orm(column_type = "Text", nullable)]
    pub retiring_key_fp: Option<String>,
}

impl Model {
    /// The parsed storage config. Errors (rather than falling back) if the stored
    /// value can't be deserialized, so a corrupt config surfaces instead of
    /// silently reverting to disk.
    pub fn recordings_storage_config(&self) -> Result<RecordingsStorageConfig, serde_json::Error> {
        serde_json::from_str(&self.recordings_storage)
    }

    /// The login banner shown to connecting clients, or `None` when it's blank.
    pub fn banner_text(&self) -> Option<&str> {
        Some(self.banner.trim()).filter(|text| !text.is_empty())
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl Model {
    pub const fn effective_mfa_enforcement_for_user(
        &self,
        has_sso_credential: bool,
    ) -> MfaEnforcement {
        if self.mfa_policy_exempt_sso_users && has_sso_credential {
            MfaEnforcement::Off
        } else {
            self.mfa_enforcement
        }
    }

    pub const fn mfa_required_factor(
        &self,
        protocol: Protocol,
        has_sso: bool,
        has_totp: bool,
    ) -> Option<CredentialKind> {
        match (self.effective_mfa_enforcement_for_user(has_sso), protocol) {
            (MfaEnforcement::Off, _) => None,
            (_, Protocol::Http) => {
                if has_totp {
                    Some(CredentialKind::Totp)
                } else {
                    // users without TOTP can still log in and will get enrolled
                    None
                }
            }
            (MfaEnforcement::Enroll, _) => None,
            // Protocols that can prompt for an OTP
            (MfaEnforcement::Require, Protocol::Ssh | Protocol::Rdp | Protocol::Vnc) => {
                Some(if has_totp {
                    CredentialKind::Totp
                } else {
                    CredentialKind::WebUserApproval
                })
            }
            // Protocols that can't prompt for an OTP
            (
                MfaEnforcement::Require,
                Protocol::MySql | Protocol::Postgres | Protocol::Kubernetes,
            ) => Some(CredentialKind::WebUserApproval),
        }
    }

    pub fn mfa_required_factors(
        &self,
        credentials: &[UserAuthCredential],
    ) -> HashMap<Protocol, CredentialKind> {
        let has = |kind| credentials.iter().any(|c| c.kind() == kind);
        let has_sso = has(CredentialKind::Sso);
        let has_totp = has(CredentialKind::Totp);
        Protocol::all()
            .filter_map(|protocol| {
                self.mfa_required_factor(protocol, has_sso, has_totp)
                    .map(|factor| (protocol, factor))
            })
            .collect()
    }

    pub fn password_policy(&self) -> PasswordPolicy {
        PasswordPolicy {
            min_length: self.password_policy_min_length.max(0) as u32,
            require_uppercase: self.password_policy_require_uppercase,
            require_lowercase: self.password_policy_require_lowercase,
            require_digits: self.password_policy_require_digits,
            require_special: self.password_policy_require_special,
        }
    }

    pub fn default_credential_policy(&self) -> serde_json::Result<UserRequireCredentialsPolicy> {
        serde_json::from_str(&self.default_credential_policy)
    }
}

impl Entity {
    pub async fn get(db: &DatabaseConnection) -> Result<Model, DbErr> {
        match Self::find().one(db).await? {
            Some(model) => Ok(model),
            None => {
                #[allow(clippy::unwrap_used, reason = "can't fail")]
                ActiveModel {
                    id: Set(Uuid::new_v4()),
                    allow_own_credential_management: Set(true),
                    rate_limit_bytes_per_second: Set(None),
                    ca_certificate_pem: Set("".into()),
                    ca_private_key_pem: Set("".into()),
                    ssh_client_auth_publickey: Set(true),
                    ssh_client_auth_password: Set(true),
                    ssh_client_auth_keyboard_interactive: Set(true),
                    ssh_host_key_verification: Set(
                        get_config_migration_values().ssh_host_key_verification
                    ),
                    password_login_mode: Set(PasswordLoginMode::Enabled),
                    mfa_enforcement: Set(MfaEnforcement::Off),
                    mfa_policy_exempt_sso_users: Set(false),
                    ticket_self_service_enabled: Set(false),
                    ticket_auto_approve_existing_access: Set(true),
                    ticket_max_duration_seconds: Set(Some(28800)),
                    ticket_max_uses: Set(None),
                    ticket_require_description: Set(false),
                    ticket_request_show_all_targets: Set(false),
                    target_click_action: Set(TargetClickAction::Connect),
                    open_targets_in_new_tab: Set(OpenTargetsInNewTabMode::DefaultOn),
                    show_session_menu: Set(true),
                    password_policy_min_length: Set(0),
                    password_policy_require_uppercase: Set(false),
                    password_policy_require_lowercase: Set(false),
                    password_policy_require_digits: Set(false),
                    password_policy_require_special: Set(false),
                    max_api_token_duration_seconds: Set(None),
                    record_scp: Set(true),
                    record_desktop_keyboard_input: Set(true),
                    tutorial_dismissed: Set(false),
                    login_protection_enabled: Set(true),
                    login_protection_retention_seconds: Set(2_592_000), // 30d
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
                    banner: Set("".into()),
                    web_clients_enabled: Set(true),
                    analytics_consent: Set(AnalyticsConsent::Undecided),
                    analytics_normal: Set(false),
                    analytics_instance_id: Set(Uuid::new_v4().to_string()),
                    instance_created_at: Set(OffsetDateTime::now_utc()),
                    web_auth_max_age_seconds: Set(None),
                    web_approval_grace_period_seconds: Set(None),
                    recordings_enable: Set(false),
                    recordings_storage: Set(serde_json::to_string(
                        &RecordingsStorageConfig::default(),
                    )
                    .unwrap()),
                    default_credential_policy: Set(serde_json::to_string(
                        &UserRequireCredentialsPolicy::default(),
                    )
                    .unwrap()),

                    cluster_token: Set(None),
                    encryption_key_fp: Set(None),
                    retiring_key_fp: Set(None),
                }
                .insert(db)
                .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use warpgate_common::{Secret, UserSsoCredential, UserTotpCredential};

    use super::*;

    fn totp_credential() -> UserAuthCredential {
        UserAuthCredential::Totp(UserTotpCredential {
            key: Secret::new(vec![]),
        })
    }

    fn sso_credential() -> UserAuthCredential {
        UserAuthCredential::Sso(UserSsoCredential {
            provider: None,
            email: "user@example.com".into(),
        })
    }

    fn parameters(mode: MfaEnforcement, exempt_sso: bool) -> Model {
        Model {
            mfa_enforcement: mode,
            mfa_policy_exempt_sso_users: exempt_sso,
            ..parameters_defaults()
        }
    }

    fn parameters_defaults() -> Model {
        Model {
            id: Uuid::nil(),
            allow_own_credential_management: true,
            rate_limit_bytes_per_second: None,
            ca_certificate_pem: "".into(),
            ca_private_key_pem: "".into(),
            ssh_client_auth_publickey: true,
            ssh_client_auth_password: true,
            ssh_client_auth_keyboard_interactive: true,
            ssh_host_key_verification: SshHostKeyVerificationMode::Prompt,
            password_login_mode: PasswordLoginMode::Enabled,
            mfa_enforcement: MfaEnforcement::Off,
            mfa_policy_exempt_sso_users: false,
            ticket_self_service_enabled: false,
            ticket_auto_approve_existing_access: true,
            ticket_max_duration_seconds: None,
            ticket_max_uses: None,
            ticket_require_description: false,
            ticket_request_show_all_targets: false,
            target_click_action: TargetClickAction::Connect,
            open_targets_in_new_tab: OpenTargetsInNewTabMode::DefaultOn,
            show_session_menu: true,
            password_policy_min_length: 0,
            password_policy_require_uppercase: false,
            password_policy_require_lowercase: false,
            password_policy_require_digits: false,
            password_policy_require_special: false,
            max_api_token_duration_seconds: None,
            record_scp: true,
            record_desktop_keyboard_input: true,
            tutorial_dismissed: false,
            login_protection_enabled: false,
            login_protection_retention_seconds: 0,
            lp_ip_max_attempts: 0,
            lp_ip_time_window_seconds: 0,
            lp_ip_base_block_duration_seconds: 0,
            lp_ip_block_duration_multiplier: 0.0,
            lp_ip_max_block_duration_seconds: 0,
            lp_ip_cooldown_reset_seconds: 0,
            lp_user_max_attempts: 0,
            lp_user_time_window_seconds: 0,
            lp_user_auto_unlock: false,
            lp_user_lockout_duration_seconds: 0,
            lp_user_exempt_admins: false,
            banner: "".into(),
            web_clients_enabled: true,
            analytics_consent: AnalyticsConsent::Undecided,
            analytics_normal: false,
            analytics_instance_id: "".into(),
            instance_created_at: OffsetDateTime::UNIX_EPOCH,
            web_auth_max_age_seconds: None,
            web_approval_grace_period_seconds: None,
            recordings_enable: false,
            recordings_storage: "".into(),
            default_credential_policy: "{}".into(),
            cluster_token: None,
            encryption_key_fp: None,
            retiring_key_fp: None,
        }
    }

    #[test]
    fn mfa_required_factors_off_is_empty() {
        let params = parameters(MfaEnforcement::Off, false);
        assert!(params.mfa_required_factors(&[totp_credential()]).is_empty());
    }

    #[test]
    fn mfa_required_factors_exempts_sso_users() {
        let params = parameters(MfaEnforcement::Require, true);
        assert!(
            params
                .mfa_required_factors(&[sso_credential(), totp_credential()])
                .is_empty()
        );
        assert!(!params.mfa_required_factors(&[totp_credential()]).is_empty());
    }

    #[test]
    fn mfa_required_factors_enroll_only_binds_http_for_enrolled_users() {
        let params = parameters(MfaEnforcement::Enroll, false);

        // Unenrolled users must be able to log in to reach the setup flow
        assert!(params.mfa_required_factors(&[]).is_empty());

        let factors = params.mfa_required_factors(&[totp_credential()]);
        assert_eq!(factors.len(), 1);
        assert_eq!(factors.get(&Protocol::Http), Some(&CredentialKind::Totp));
    }

    #[test]
    fn mfa_required_factors_require_covers_all_protocols() {
        let params = parameters(MfaEnforcement::Require, false);

        let factors = params.mfa_required_factors(&[totp_credential()]);
        for protocol in Protocol::all() {
            assert!(factors.contains_key(&protocol), "{protocol}");
        }
        assert_eq!(factors.get(&Protocol::Http), Some(&CredentialKind::Totp));
        assert_eq!(factors.get(&Protocol::Ssh), Some(&CredentialKind::Totp));
        assert_eq!(factors.get(&Protocol::Rdp), Some(&CredentialKind::Totp));
        assert_eq!(factors.get(&Protocol::Vnc), Some(&CredentialKind::Totp));
        for protocol in [Protocol::MySql, Protocol::Postgres, Protocol::Kubernetes] {
            assert_eq!(
                factors.get(&protocol),
                Some(&CredentialKind::WebUserApproval)
            );
        }

        // No OTP: HTTP lets the user in to enroll; every other protocol
        // requires a factor, with web approval standing in for the missing OTP
        let factors = params.mfa_required_factors(&[]);
        assert_eq!(factors.get(&Protocol::Http), None);
        for protocol in Protocol::all().filter(|p| *p != Protocol::Http) {
            assert_eq!(
                factors.get(&protocol),
                Some(&CredentialKind::WebUserApproval),
                "{protocol}"
            );
        }
    }

    #[test]
    fn storage_config_roundtrips() {
        use warpgate_aws::{AutoCredentials, S3Credentials, StaticCredentials};

        for config in [
            RecordingsStorageConfig::default(),
            RecordingsStorageConfig::Disk(RecordingsDiskConfig {
                path: "/tmp/rec".into(),
            }),
            RecordingsStorageConfig::S3(S3StorageConfig {
                bucket: "b".into(),
                region: "us-east-1".into(),
                endpoint: Some("http://minio:9000".into()),
                path_style: true,
                prefix: "p/".into(),
                credentials: S3Credentials::Auto(AutoCredentials {}),
            }),
            RecordingsStorageConfig::S3(S3StorageConfig {
                bucket: "b".into(),
                region: "eu-west-1".into(),
                endpoint: None,
                path_style: false,
                prefix: String::new(),
                credentials: S3Credentials::Static(StaticCredentials {
                    access_key_id: "AKIA".into(),
                    secret_access_key: Some("secret".into()),
                }),
            }),
        ] {
            let json = serde_json::to_string(&config).unwrap();
            assert_eq!(
                serde_json::from_str::<RecordingsStorageConfig>(&json).unwrap(),
                config,
            );
        }
    }
}
