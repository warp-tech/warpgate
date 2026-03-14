use poem::web::Data;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use russh::keys::PublicKeyBase64;
use serde::Serialize;
use warpgate_common::WarpgateError;
use warpgate_common_http::AuthenticatedRequestContext;

use super::AnySecurityScheme;
use crate::api::common::require_admin_permission;

pub struct Api;

#[derive(Serialize, Object)]
struct SSHKey {
    pub kind: String,
    pub public_key_base64: String,
}

#[derive(ApiResponse)]
enum GetSSHOwnKeysResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<SSHKey>>),
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/ssh/own-keys",
        method = "get",
        operation_id = "get_ssh_own_keys"
    )]
    async fn api_ssh_get_own_keys(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetSSHOwnKeysResponse, WarpgateError> {
        require_admin_permission(&ctx, None).await?;

        let config = ctx.services.config.lock().await;
        let keys =
            warpgate_protocol_ssh::load_keys(&config, &ctx.services.global_params, "client")?;

        let keys = keys
            .into_iter()
            .map(|k| SSHKey {
                kind: k.algorithm().to_string(),
                public_key_base64: k.public_key_base64(),
            })
            .collect();
        Ok(GetSSHOwnKeysResponse::Ok(Json(keys)))
    }
}
