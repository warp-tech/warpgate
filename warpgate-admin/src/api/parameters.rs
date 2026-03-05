use poem::web::Data;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::ActiveValue::NotSet;
use sea_orm::{EntityTrait, IntoActiveModel, Set};
use serde::Serialize;
use warpgate_common::WarpgateError;
use warpgate_core::Services;
use warpgate_db_entities::Parameters;

use super::AnySecurityScheme;

pub struct Api;

#[derive(Serialize, Object)]
struct ParameterValues {
    pub allow_own_credential_management: bool,
    pub rate_limit_bytes_per_second: Option<u32>,
    pub ssh_client_auth_publickey: bool,
    pub ssh_client_auth_password: bool,
    pub ssh_client_auth_keyboard_interactive: bool,
    /// Hash threshold for file transfers in bytes (files larger than this won't be hashed)
    pub file_transfer_hash_threshold_bytes: Option<i64>,
    /// SFTP permission enforcement mode: "strict" or "permissive"
    /// - strict: Shell/exec/forwarding blocked when SFTP restrictions are active
    /// - permissive: SFTP enforced but shell/exec/forwarding still allowed
    pub sftp_permission_mode: String,
}

#[derive(Serialize, Object)]
struct ParameterUpdate {
    pub allow_own_credential_management: bool,
    pub rate_limit_bytes_per_second: Option<u32>,
    pub ssh_client_auth_publickey: Option<bool>,
    pub ssh_client_auth_password: Option<bool>,
    pub ssh_client_auth_keyboard_interactive: Option<bool>,
    /// Hash threshold for file transfers in bytes (files larger than this won't be hashed)
    pub file_transfer_hash_threshold_bytes: Option<i64>,
    /// SFTP permission enforcement mode: "strict" or "permissive"
    /// - strict: Shell/exec/forwarding blocked when SFTP restrictions are active
    /// - permissive: SFTP enforced but shell/exec/forwarding still allowed
    pub sftp_permission_mode: Option<String>,
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
        services: Data<&Services>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetParametersResponse, WarpgateError> {
        let db = services.db.lock().await;
        let parameters = Parameters::Entity::get(&db).await?;

        Ok(GetParametersResponse::Ok(Json(ParameterValues {
            allow_own_credential_management: parameters.allow_own_credential_management,
            rate_limit_bytes_per_second: parameters.rate_limit_bytes_per_second.map(|x| x as u32),
            ssh_client_auth_publickey: parameters.ssh_client_auth_publickey,
            ssh_client_auth_password: parameters.ssh_client_auth_password,
            ssh_client_auth_keyboard_interactive: parameters.ssh_client_auth_keyboard_interactive,
            file_transfer_hash_threshold_bytes: parameters.file_transfer_hash_threshold_bytes,
            sftp_permission_mode: parameters.sftp_permission_mode,
        })))
    }

    #[oai(
        path = "/parameters",
        method = "put",
        operation_id = "update_parameters"
    )]
    async fn api_update_parameters(
        &self,
        services: Data<&Services>,
        body: Json<ParameterUpdate>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<UpdateParametersResponse, WarpgateError> {
        let db = services.db.lock().await;
        let mut parameters = Parameters::Entity::get(&db).await?.into_active_model();

        parameters.allow_own_credential_management = Set(body.allow_own_credential_management);
        parameters.rate_limit_bytes_per_second =
            Set(body.rate_limit_bytes_per_second.map(|x| x as i64));
        parameters.ssh_client_auth_publickey = body.ssh_client_auth_publickey.map_or(NotSet, Set);
        parameters.ssh_client_auth_password = body.ssh_client_auth_password.map_or(NotSet, Set);
        parameters.ssh_client_auth_keyboard_interactive = body
            .ssh_client_auth_keyboard_interactive
            .map_or(NotSet, Set);
        parameters.file_transfer_hash_threshold_bytes =
            Set(body.file_transfer_hash_threshold_bytes);

        // Validate and set sftp_permission_mode if provided
        if let Some(ref mode) = body.sftp_permission_mode {
            if mode != "strict" && mode != "permissive" {
                return Err(anyhow::anyhow!(
                    "sftp_permission_mode must be 'strict' or 'permissive'"
                )
                .into());
            }
            parameters.sftp_permission_mode = Set(mode.clone());
        }

        Parameters::Entity::update(parameters).exec(&*db).await?;
        drop(db);

        services
            .rate_limiter_registry
            .lock()
            .await
            .apply_new_rate_limits(&mut *services.state.lock().await)
            .await?;

        Ok(UpdateParametersResponse::Done)
    }
}
