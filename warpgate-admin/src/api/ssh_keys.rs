use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use russh::keys::PublicKeyBase64;
use serde::Serialize;
use warpgate_common::WarpgateError;

use super::AdminContext;

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
        admin: AdminContext,
    ) -> Result<GetSSHOwnKeysResponse, WarpgateError> {
        let config = admin.services().config.lock().await;
        let keys =
            warpgate_protocol_ssh::load_keys(&config, &admin.services().global_params, "client")?;

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
