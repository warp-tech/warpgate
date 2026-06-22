use poem::web::Data;
use poem_openapi::payload::{Json, PlainText};
use poem_openapi::{ApiResponse, Object, OpenApi};
use russh::keys::PublicKeyBase64;
use uuid::Uuid;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_protocol_ssh::{RCCommand, RCEvent, RemoteClient, resolve_ssh_chain};

use super::AnySecurityScheme;
use crate::api::common::require_admin_permission;

pub struct Api;

#[derive(Object)]
struct CheckSshHostKeyRequest {
    target_id: Uuid,
}

#[derive(Object)]
struct CheckSshHostKeyResponseBody {
    remote_key_type: String,
    remote_key_base64: String,
}

#[derive(ApiResponse)]
enum CheckSshHostKeyResponse {
    #[oai(status = 200)]
    Ok(Json<CheckSshHostKeyResponseBody>),
    #[oai(status = 500)]
    Error(PlainText<String>),
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/ssh/check-host-key",
        method = "post",
        operation_id = "check_ssh_host_key"
    )]
    async fn api_ssh_check_host_key(
        &self,
        ctx: Data<&AuthenticatedRequestContext>,
        body: Json<CheckSshHostKeyRequest>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<CheckSshHostKeyResponse, WarpgateError> {
        require_admin_permission(&ctx, Some(AdminPermission::TargetsEdit)).await?;

        let ssh_chain = resolve_ssh_chain(ctx.services(), body.target_id, ctx.auth.username())
            .await?
            .into_iter()
            .map(|x| x.ssh_options)
            .collect::<Vec<_>>();

        let mut handles = RemoteClient::create(Uuid::new_v4(), ctx.services().clone())?;
        let _ = handles
            .command_tx
            .send((RCCommand::Connect(ssh_chain), None));

        let fut = async move {
            let key = loop {
                match handles.event_rx.recv().await {
                    Some(RCEvent::HostKeyReceived(key)) => break key,
                    Some(RCEvent::HostKeyUnknown(key, reply)) => {
                        let _ = reply.send(true);
                        break key;
                    }
                    Some(RCEvent::ConnectionError(err)) => return Err(anyhow::Error::from(err)),
                    Some(RCEvent::Error(err)) => return Err(err),
                    None => anyhow::bail!("Failed to connect to target"),
                    _ => (),
                }
            };
            anyhow::Ok(key)
        };

        // Result is matched manually since we need to manually format
        // the error message with :# to included the nested errors here
        match fut.await {
            Ok(key) => Ok(CheckSshHostKeyResponse::Ok(Json(
                CheckSshHostKeyResponseBody {
                    remote_key_type: key.algorithm().as_str().into(),
                    remote_key_base64: key.public_key_base64(),
                },
            ))),
            Err(err) => Ok(CheckSshHostKeyResponse::Error(PlainText(format!(
                "{err:#}"
            )))),
        }
    }
}
