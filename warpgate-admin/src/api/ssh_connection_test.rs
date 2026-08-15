use poem_openapi::payload::{Json, PlainText};
use poem_openapi::{ApiResponse, Object, OpenApi};
use russh::keys::PublicKeyBase64;
use uuid::Uuid;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_protocol_ssh::{ConnectionError, RCCommand, RCEvent, RemoteClient, resolve_ssh_chain};

use super::AdminContext;

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
        admin: AdminContext,
        body: Json<CheckSshHostKeyRequest>,
    ) -> Result<CheckSshHostKeyResponse, WarpgateError> {
        admin.require(AdminPermission::TargetsEdit)?;

        let ssh_chain =
            resolve_ssh_chain(admin.services(), body.target_id, admin.auth.username()).await?;

        let mut handles = RemoteClient::create(Uuid::new_v4(), admin.services().clone())?;
        // Not `Connect`: that would carry on into authenticating to the target
        // once the key had been reported, opening a session nothing is attached
        // to — and, for a certificate target, minting a real certificate to do
        // it with.
        let _ = handles.command_tx.send((
            RCCommand::CheckHostKey {
                chain: ssh_chain,
                // By identity. Which hop answers is decided by which target was
                // asked about, not by which happens to be last.
                target_id: body.target_id,
                requested_by: admin.auth.attribution().to_owned(),
            },
            None,
        ));

        // Kept out of the future below so the connection can be torn down after
        // it resolves. `CheckHostKey` already ends the client task on its own;
        // this is the second lock on the same door, scoped to this caller so
        // that a real session's graceful disconnect stays untouched.
        let abort_tx = handles.abort_tx.clone();

        let fut = async move {
            let key = loop {
                match handles.event_rx.recv().await {
                    Some(RCEvent::HostKeyReceived(key)) => break key,
                    Some(RCEvent::HostKeyUnknown(key, _, _, reply)) => {
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

        let result = fut.await;
        let _ = abort_tx.send(());

        // Sanitised, like every other place a connection error is shown to a
        // person. Reaching a target behind a jump host authenticates that hop,
        // so a Vault failure is reachable here and used to be rendered with its
        // whole source chain — mount, policy and all.
        match result {
            Ok(key) => Ok(CheckSshHostKeyResponse::Ok(Json(
                CheckSshHostKeyResponseBody {
                    remote_key_type: key.algorithm().as_str().into(),
                    remote_key_base64: key.public_key_base64(),
                },
            ))),
            Err(err) => Ok(CheckSshHostKeyResponse::Error(PlainText(
                err.downcast_ref::<ConnectionError>()
                    .map_or_else(|| format!("{err:#}"), ConnectionError::client_message),
            ))),
        }
    }
}
