use crate::helpers::{authorized, ApiResult};
use poem::session::Session;
use poem::web::Data;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use russh_keys::PublicKeyBase64;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::Mutex;
use warpgate_common::WarpgateConfig;

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
        config: Data<&Arc<Mutex<WarpgateConfig>>>,
        session: &Session,
    ) -> ApiResult<GetSSHOwnKeysResponse> {
        authorized(session, || async move {
            let config = config.lock().await;
            let keys = warpgate_protocol_ssh::load_client_keys(&config)
                .map_err(poem::error::InternalServerError)?;

            let keys = keys
                .into_iter()
                .map(|k| SSHKey {
                    kind: k.name().to_owned(),
                    public_key_base64: k.public_key_base64().replace("\n", "").replace("\r", ""),
                })
                .collect();
            Ok(GetSSHOwnKeysResponse::Ok(Json(keys)))
        })
        .await
    }
}
