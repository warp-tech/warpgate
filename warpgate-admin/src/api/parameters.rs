use poem::web::Data;
use poem_openapi::param::Query;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::ActiveValue::NotSet;
use sea_orm::{EntityTrait, IntoActiveModel, Set};
use serde::Serialize;
use warpgate_aws::{S3Credentials, S3Storage};
use warpgate_common::{AdminPermission, PasswordPolicy, WarpgateError};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_db_entities::Parameters;
use warpgate_db_entities::Parameters::RecordingsStorageConfig;

use super::AnySecurityScheme;
use crate::api::common::require_admin_permission;

pub struct Api;

/// The stored S3 secret is never sent to the browser.
fn redact_secret(mut config: RecordingsStorageConfig) -> RecordingsStorageConfig {
    if let RecordingsStorageConfig::S3(s3) = &mut config
        && let S3Credentials::Static(creds) = &mut s3.credentials
    {
        creds.secret_access_key = None;
    }
    config
}

/// A `None` incoming secret keeps the one already stored (the UI never sees it,
/// so it round-trips the redacted `None` unless the admin types a new value).
fn merge_secret(
    mut incoming: RecordingsStorageConfig,
    current: &RecordingsStorageConfig,
) -> RecordingsStorageConfig {
    if let RecordingsStorageConfig::S3(s3) = &mut incoming
        && let S3Credentials::Static(creds) = &mut s3.credentials
        && creds.secret_access_key.is_none()
        && let RecordingsStorageConfig::S3(current_s3) = current
        && let S3Credentials::Static(current_creds) = &current_s3.credentials
    {
        creds
            .secret_access_key
            .clone_from(&current_creds.secret_access_key);
    }
    incoming
}

#[derive(Serialize, Object)]
struct ParameterValues {
    pub allow_own_credential_management: bool,
    pub rate_limit_bytes_per_second: Option<u32>,
    pub ssh_client_auth_publickey: bool,
    pub ssh_client_auth_password: bool,
    pub ssh_client_auth_keyboard_interactive: bool,
    pub password_login_mode: Parameters::PasswordLoginMode,
    /// Deprecated in 0.26: superseded by `password_login_mode`
    pub minimize_password_login: bool,
    pub ticket_self_service_enabled: bool,
    pub ticket_auto_approve_existing_access: bool,
    pub ticket_max_duration_seconds: Option<i64>,
    pub ticket_max_uses: Option<i16>,
    pub ticket_require_description: bool,
    pub ticket_request_show_all_targets: bool,
    pub target_click_action: Parameters::TargetClickAction,
    pub show_session_menu: bool,
    pub password_policy: PasswordPolicy,
    pub max_api_token_duration_seconds: Option<i64>,
    pub record_scp: bool,
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
    pub ssh_banner: String,
    /// Deprecated in 0.27: superseded by `web_clients_enabled`
    pub web_ssh_enabled: bool,
    pub web_clients_enabled: bool,
    pub web_auth_max_age_seconds: Option<i64>,
    pub web_approval_grace_period_seconds: Option<i64>,
    pub admin_approval_timeout_seconds: Option<i64>,
    pub admin_approval_grace_period_seconds: Option<i64>,
    pub analytics_consent: Parameters::AnalyticsConsent,
    pub analytics_normal: bool,
    pub recordings_enable: bool,
    pub recordings_storage: RecordingsStorageConfig,
}

#[derive(Serialize, Object)]
struct ParameterUpdate {
    pub allow_own_credential_management: Option<bool>,
    pub rate_limit_bytes_per_second: Option<u32>,
    pub ssh_client_auth_publickey: Option<bool>,
    pub ssh_client_auth_password: Option<bool>,
    pub ssh_client_auth_keyboard_interactive: Option<bool>,
    pub password_login_mode: Option<Parameters::PasswordLoginMode>,
    pub ticket_self_service_enabled: Option<bool>,
    pub ticket_auto_approve_existing_access: Option<bool>,
    pub ticket_max_duration_seconds: Option<Option<i64>>,
    pub ticket_max_uses: Option<Option<i16>>,
    pub ticket_require_description: Option<bool>,
    pub ticket_request_show_all_targets: Option<bool>,
    pub target_click_action: Option<Parameters::TargetClickAction>,
    pub show_session_menu: Option<bool>,
    pub password_policy: Option<PasswordPolicy>,
    pub max_api_token_duration_seconds: Option<Option<i64>>,
    pub record_scp: Option<bool>,
    pub login_protection_enabled: Option<bool>,
    pub login_protection_retention_seconds: Option<i32>,
    pub lp_ip_max_attempts: Option<i32>,
    pub lp_ip_time_window_seconds: Option<i32>,
    pub lp_ip_base_block_duration_seconds: Option<i32>,
    pub lp_ip_block_duration_multiplier: Option<f64>,
    pub lp_ip_max_block_duration_seconds: Option<i32>,
    pub lp_ip_cooldown_reset_seconds: Option<i32>,
    pub lp_user_max_attempts: Option<i32>,
    pub lp_user_time_window_seconds: Option<i32>,
    pub lp_user_auto_unlock: Option<bool>,
    pub lp_user_lockout_duration_seconds: Option<i32>,
    pub lp_user_exempt_admins: Option<bool>,
    pub ssh_banner: Option<String>,
    pub web_clients_enabled: Option<bool>,
    pub web_auth_max_age_seconds: Option<Option<i64>>,
    pub web_approval_grace_period_seconds: Option<Option<i64>>,
    pub admin_approval_timeout_seconds: Option<Option<i64>>,
    pub admin_approval_grace_period_seconds: Option<Option<i64>>,
    pub analytics_consent: Option<Parameters::AnalyticsConsent>,
    pub analytics_normal: Option<bool>,
    pub recordings_enable: Option<bool>,
    pub recordings_storage: Option<RecordingsStorageConfig>,
}

#[derive(Serialize, Object)]
struct AnalyticsPreview {
    /// The target URL the report would be POSTed to.
    url: String,
    /// Pretty-printed JSON request body that would be sent.
    payload: String,
}

#[derive(ApiResponse)]
enum GetParametersResponse {
    #[oai(status = 200)]
    Ok(Json<ParameterValues>),
}

#[derive(ApiResponse)]
enum GetAnalyticsPreviewResponse {
    #[oai(status = 200)]
    Ok(Json<AnalyticsPreview>),
}

#[derive(ApiResponse)]
enum UpdateParametersResponse {
    #[oai(status = 201)]
    Done,
}

#[derive(Serialize, Object)]
struct TestRecordingsStorageResult {
    /// Whether the backend accepted a write/delete round-trip.
    success: bool,
    /// The failure message when `success` is false.
    error: Option<String>,
}

#[derive(ApiResponse)]
enum TestRecordingsStorageResponse {
    #[oai(status = 200)]
    Ok(Json<TestRecordingsStorageResult>),
}

#[OpenApi]
impl Api {
    #[oai(path = "/parameters", method = "get", operation_id = "get_parameters")]
    async fn api_get(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetParametersResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;

        let parameters = ctx.parameters().await?.clone();
        let recordings_storage = redact_secret(parameters.recordings_storage_config()?);

        Ok(GetParametersResponse::Ok(Json(ParameterValues {
            allow_own_credential_management: parameters.allow_own_credential_management,
            rate_limit_bytes_per_second: parameters.rate_limit_bytes_per_second.map(|x| x as u32),
            ssh_client_auth_publickey: parameters.ssh_client_auth_publickey,
            ssh_client_auth_password: parameters.ssh_client_auth_password,
            ssh_client_auth_keyboard_interactive: parameters.ssh_client_auth_keyboard_interactive,
            password_login_mode: parameters.password_login_mode,
            minimize_password_login: parameters.password_login_mode
                == Parameters::PasswordLoginMode::Minimized,
            ticket_self_service_enabled: parameters.ticket_self_service_enabled,
            ticket_auto_approve_existing_access: parameters.ticket_auto_approve_existing_access,
            ticket_max_duration_seconds: parameters.ticket_max_duration_seconds,
            ticket_max_uses: parameters.ticket_max_uses,
            ticket_require_description: parameters.ticket_require_description,
            ticket_request_show_all_targets: parameters.ticket_request_show_all_targets,
            target_click_action: parameters.target_click_action,
            show_session_menu: parameters.show_session_menu,
            password_policy: parameters.password_policy(),
            max_api_token_duration_seconds: parameters.max_api_token_duration_seconds,
            record_scp: parameters.record_scp,
            login_protection_enabled: parameters.login_protection_enabled,
            login_protection_retention_seconds: parameters.login_protection_retention_seconds,
            lp_ip_max_attempts: parameters.lp_ip_max_attempts,
            lp_ip_time_window_seconds: parameters.lp_ip_time_window_seconds,
            lp_ip_base_block_duration_seconds: parameters.lp_ip_base_block_duration_seconds,
            lp_ip_block_duration_multiplier: parameters.lp_ip_block_duration_multiplier,
            lp_ip_max_block_duration_seconds: parameters.lp_ip_max_block_duration_seconds,
            lp_ip_cooldown_reset_seconds: parameters.lp_ip_cooldown_reset_seconds,
            lp_user_max_attempts: parameters.lp_user_max_attempts,
            lp_user_time_window_seconds: parameters.lp_user_time_window_seconds,
            lp_user_auto_unlock: parameters.lp_user_auto_unlock,
            lp_user_lockout_duration_seconds: parameters.lp_user_lockout_duration_seconds,
            lp_user_exempt_admins: parameters.lp_user_exempt_admins,
            ssh_banner: parameters.ssh_banner,
            web_ssh_enabled: parameters.web_clients_enabled,
            web_clients_enabled: parameters.web_clients_enabled,
            web_auth_max_age_seconds: parameters.web_auth_max_age_seconds,
            web_approval_grace_period_seconds: parameters.web_approval_grace_period_seconds,
            admin_approval_timeout_seconds: parameters.admin_approval_timeout_seconds,
            admin_approval_grace_period_seconds: parameters.admin_approval_grace_period_seconds,
            analytics_consent: parameters.analytics_consent,
            analytics_normal: parameters.analytics_normal,
            recordings_enable: parameters.recordings_enable,
            recordings_storage,
        })))
    }

    #[oai(
        path = "/parameters/analytics-preview",
        method = "get",
        operation_id = "get_analytics_preview"
    )]
    async fn api_analytics_preview(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        normal: Query<bool>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetAnalyticsPreviewResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::ConfigEdit)).await?;

        let (url, payload) =
            warpgate_core::analytics::preview(&ctx.services().db, normal.0).await?;

        Ok(GetAnalyticsPreviewResponse::Ok(Json(AnalyticsPreview {
            url,
            payload: serde_json::to_string_pretty(&payload)?,
        })))
    }

    #[oai(
        path = "/parameters",
        method = "put",
        operation_id = "update_parameters"
    )]
    async fn api_update_parameters(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        body: Json<ParameterUpdate>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<UpdateParametersResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::ConfigEdit)).await?;

        let services = ctx.services();
        let db = &services.db;
        let current = ctx.parameters().await?.clone();
        let storage = match &body.recordings_storage {
            Some(incoming) => Some(serde_json::to_string(&merge_secret(
                incoming.clone(),
                &current.recordings_storage_config()?,
            ))?),
            None => None,
        };
        let mut parameters = current.into_active_model();

        parameters.allow_own_credential_management =
            body.allow_own_credential_management.map_or(NotSet, Set);
        parameters.rate_limit_bytes_per_second =
            Set(body.rate_limit_bytes_per_second.map(i64::from));
        parameters.ssh_client_auth_publickey = body.ssh_client_auth_publickey.map_or(NotSet, Set);
        parameters.ssh_client_auth_password = body.ssh_client_auth_password.map_or(NotSet, Set);
        parameters.ssh_client_auth_keyboard_interactive = body
            .ssh_client_auth_keyboard_interactive
            .map_or(NotSet, Set);
        parameters.password_login_mode = body.password_login_mode.map_or(NotSet, Set);
        parameters.ticket_self_service_enabled =
            body.ticket_self_service_enabled.map_or(NotSet, Set);
        parameters.ticket_auto_approve_existing_access =
            body.ticket_auto_approve_existing_access.map_or(NotSet, Set);
        parameters.ticket_max_duration_seconds =
            body.ticket_max_duration_seconds.map_or(NotSet, Set);
        parameters.ticket_max_uses = body.ticket_max_uses.map_or(NotSet, Set);
        parameters.ticket_require_description = body.ticket_require_description.map_or(NotSet, Set);
        parameters.ticket_request_show_all_targets =
            body.ticket_request_show_all_targets.map_or(NotSet, Set);
        parameters.target_click_action = body.target_click_action.map_or(NotSet, Set);
        parameters.show_session_menu = body.show_session_menu.map_or(NotSet, Set);
        parameters.max_api_token_duration_seconds =
            body.max_api_token_duration_seconds.map_or(NotSet, Set);
        parameters.record_scp = body.record_scp.map_or(NotSet, Set);

        #[allow(clippy::cast_possible_wrap)]
        if let Some(ref policy) = body.password_policy {
            parameters.password_policy_min_length = Set(policy.min_length as i32);
            parameters.password_policy_require_uppercase = Set(policy.require_uppercase);
            parameters.password_policy_require_lowercase = Set(policy.require_lowercase);
            parameters.password_policy_require_digits = Set(policy.require_digits);
            parameters.password_policy_require_special = Set(policy.require_special);
        }

        parameters.login_protection_enabled = body.login_protection_enabled.map_or(NotSet, Set);
        parameters.login_protection_retention_seconds =
            body.login_protection_retention_seconds.map_or(NotSet, Set);
        parameters.lp_ip_max_attempts = body.lp_ip_max_attempts.map_or(NotSet, Set);
        parameters.lp_ip_time_window_seconds = body.lp_ip_time_window_seconds.map_or(NotSet, Set);
        parameters.lp_ip_base_block_duration_seconds =
            body.lp_ip_base_block_duration_seconds.map_or(NotSet, Set);
        parameters.lp_ip_block_duration_multiplier =
            body.lp_ip_block_duration_multiplier.map_or(NotSet, Set);
        parameters.lp_ip_max_block_duration_seconds =
            body.lp_ip_max_block_duration_seconds.map_or(NotSet, Set);
        parameters.lp_ip_cooldown_reset_seconds =
            body.lp_ip_cooldown_reset_seconds.map_or(NotSet, Set);
        parameters.lp_user_max_attempts = body.lp_user_max_attempts.map_or(NotSet, Set);
        parameters.lp_user_time_window_seconds =
            body.lp_user_time_window_seconds.map_or(NotSet, Set);
        parameters.lp_user_auto_unlock = body.lp_user_auto_unlock.map_or(NotSet, Set);
        parameters.lp_user_lockout_duration_seconds =
            body.lp_user_lockout_duration_seconds.map_or(NotSet, Set);
        parameters.lp_user_exempt_admins = body.lp_user_exempt_admins.map_or(NotSet, Set);
        parameters.ssh_banner = body.ssh_banner.clone().map_or(NotSet, Set);
        parameters.web_clients_enabled = body.web_clients_enabled.map_or(NotSet, Set);
        parameters.web_auth_max_age_seconds = body.web_auth_max_age_seconds.map_or(NotSet, Set);
        parameters.web_approval_grace_period_seconds =
            body.web_approval_grace_period_seconds.map_or(NotSet, Set);
        parameters.admin_approval_timeout_seconds =
            body.admin_approval_timeout_seconds.map_or(NotSet, Set);
        parameters.admin_approval_grace_period_seconds =
            body.admin_approval_grace_period_seconds.map_or(NotSet, Set);
        parameters.analytics_consent = body.analytics_consent.map_or(NotSet, Set);
        parameters.analytics_normal = body.analytics_normal.map_or(NotSet, Set);

        parameters.recordings_enable = body.recordings_enable.map_or(NotSet, Set);
        parameters.recordings_storage = storage.map_or(NotSet, Set);

        Parameters::Entity::update(parameters).exec(db).await?;

        services
            .rate_limiter_registry
            .lock()
            .await
            .apply_new_rate_limits(&*services.state.lock().await)
            .await?;

        Ok(UpdateParametersResponse::Done)
    }

    #[oai(
        path = "/parameters/recordings-storage/test",
        method = "post",
        operation_id = "test_recordings_storage"
    )]
    async fn api_test_recordings_storage(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        body: Json<RecordingsStorageConfig>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<TestRecordingsStorageResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::ConfigEdit)).await?;

        let current = ctx.parameters().await?;
        // The UI never receives the stored secret, so fill it back in before testing.
        let config = merge_secret(body.0, &current.recordings_storage_config()?);

        let error = match config {
            RecordingsStorageConfig::S3(s3) => match S3Storage::new(&s3).await {
                Ok(storage) => storage.test().await.err().map(|e| e.to_string()),
                Err(e) => Some(e.to_string()),
            },
            // Disk is always reachable; nothing to test.
            RecordingsStorageConfig::Disk(_) => None,
        };

        Ok(TestRecordingsStorageResponse::Ok(Json(
            TestRecordingsStorageResult {
                success: error.is_none(),
                error,
            },
        )))
    }
}
