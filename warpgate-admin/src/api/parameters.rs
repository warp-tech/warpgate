use poem::web::Data;
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
    pub minimize_password_login: bool,
    pub show_session_menu: bool,
    pub password_policy: PasswordPolicy,
}

#[derive(Serialize, Object)]
struct ParameterUpdate {
    pub allow_own_credential_management: bool,
    pub rate_limit_bytes_per_second: Option<u32>,
    pub ssh_client_auth_publickey: Option<bool>,
    pub ssh_client_auth_password: Option<bool>,
    pub ssh_client_auth_keyboard_interactive: Option<bool>,
    pub minimize_password_login: Option<bool>,
    pub show_session_menu: Option<bool>,
    pub password_policy: Option<PasswordPolicy>,
}

#[derive(ApiResponse)]
enum GetParametersResponse {
    #[oai(status = 200)]
    Ok(Json<ParameterValues>),
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
            minimize_password_login: parameters.minimize_password_login,
            show_session_menu: parameters.show_session_menu,
            password_policy: parameters.password_policy(),
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

        parameters.allow_own_credential_management = Set(body.allow_own_credential_management);
        parameters.rate_limit_bytes_per_second =
            Set(body.rate_limit_bytes_per_second.map(i64::from));
        parameters.ssh_client_auth_publickey = body.ssh_client_auth_publickey.map_or(NotSet, Set);
        parameters.ssh_client_auth_password = body.ssh_client_auth_password.map_or(NotSet, Set);
        parameters.ssh_client_auth_keyboard_interactive = body
            .ssh_client_auth_keyboard_interactive
            .map_or(NotSet, Set);
        parameters.minimize_password_login = body.minimize_password_login.map_or(NotSet, Set);
        parameters.show_session_menu = body.show_session_menu.map_or(NotSet, Set);

        if let Some(ref policy) = body.password_policy {
            parameters.password_policy_min_length = Set(policy.min_length as i32);
            parameters.password_policy_require_uppercase = Set(policy.require_uppercase);
            parameters.password_policy_require_lowercase = Set(policy.require_lowercase);
            parameters.password_policy_require_digits = Set(policy.require_digits);
            parameters.password_policy_require_special = Set(policy.require_special);
        }

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
