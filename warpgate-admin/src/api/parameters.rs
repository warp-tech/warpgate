use poem::web::Data;
use poem_openapi::param::Query;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::ActiveValue::NotSet;
use sea_orm::{EntityTrait, IntoActiveModel, Set};
use serde::Serialize;
use warpgate_common::{AdminPermission, PasswordPolicy, WarpgateError};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_db_entities::Parameters;

use super::AnySecurityScheme;
use crate::api::common::require_admin_permission;

pub struct Api;

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
    pub web_clients_enabled: bool,
    pub web_auth_max_age_seconds: Option<i64>,
    pub analytics_consent: Parameters::AnalyticsConsent,
    pub analytics_normal: bool,
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
    pub analytics_consent: Option<Parameters::AnalyticsConsent>,
    pub analytics_normal: Option<bool>,
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

#[OpenApi]
impl Api {
    #[oai(path = "/parameters", method = "get", operation_id = "get_parameters")]
    async fn api_get(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetParametersResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;

        let db = ctx.services().db.lock().await;
        let parameters = Parameters::Entity::get(&db).await?;

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
            web_clients_enabled: parameters.web_clients_enabled,
            web_auth_max_age_seconds: parameters.web_auth_max_age_seconds,
            analytics_consent: parameters.analytics_consent,
            analytics_normal: parameters.analytics_normal,
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
        let db = services.db.lock().await;
        let mut parameters = Parameters::Entity::get(&db).await?.into_active_model();

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
        parameters.analytics_consent = body.analytics_consent.map_or(NotSet, Set);
        parameters.analytics_normal = body.analytics_normal.map_or(NotSet, Set);

        Parameters::Entity::update(parameters).exec(&*db).await?;
        drop(db);

        services
            .rate_limiter_registry
            .lock()
            .await
            .apply_new_rate_limits(&*services.state.lock().await)
            .await?;

        Ok(UpdateParametersResponse::Done)
    }
}
