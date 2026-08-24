use poem_openapi::payload::{Json, PlainText};
use poem_openapi::{ApiResponse, Object, OpenApi};
use russh::keys::PublicKeyBase64;
use uuid::Uuid;
use warpgate_common::{AdminPermission, UserSessionId, WarpgateError};
use warpgate_protocol_ssh::{RCCommand, RCEvent, RemoteClient, resolve_ssh_chain_for_admin};

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
            resolve_ssh_chain_for_admin(admin.services(), body.target_id, admin.auth.username())
                .await?;

        let Some(target) = ssh_chain.last() else {
            return Err(WarpgateError::InconsistentState(
                "Did not resolve SSH chain".into(),
            ));
        };
        let (target_host, target_port) = (target.ssh_options.host.clone(), target.ssh_options.port);

        let ssh_chain = ssh_chain
            .into_iter()
            .map(|x| x.ssh_options)
            .collect::<Vec<_>>();

        let mut handles =
            RemoteClient::create(UserSessionId(Uuid::new_v4()), admin.services().clone())?;
        let _ = handles
            .command_tx
            .send((RCCommand::Connect(ssh_chain), None));

        let fut = async move {
            let key = loop {
                match handles.event_rx.recv().await {
                    Some(RCEvent::HostKeyReceived(key, host, port))
                        if host == target_host && port == target_port =>
                    {
                        break key;
                    }
                    Some(RCEvent::HostKeyUnknown(_, host, port, reply)) => {
                        // this is a jump host, target key would hit  HostKeyReceived
                        let _ = reply.send(false);
                        anyhow::bail!("Jump host {host}:{port} has an untrusted host key");
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
