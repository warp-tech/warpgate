use poem::web::Data;
use poem_openapi::payload::{Json, PlainText};
use poem_openapi::{ApiResponse, Object, OpenApi};
use russh::keys::PublicKeyBase64;
use uuid::Uuid;
use warpgate_common::{SSHTargetAuth, SshTargetPasswordAuth, TargetSSHOptions, WarpgateError};
use warpgate_core::Services;
use warpgate_protocol_ssh::{RCCommand, RCEvent, RemoteClient};

use super::AnySecurityScheme;

pub struct Api;

#[derive(Object)]
struct CheckSshHostKeyRequest {
    host: String,
    port: u16,
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
        services: Data<&Services>,
        body: Json<CheckSshHostKeyRequest>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<CheckSshHostKeyResponse, WarpgateError> {
        let mut handles = RemoteClient::create(Uuid::new_v4(), services.clone())?;

        let _ = handles.command_tx.send((
            RCCommand::Connect(TargetSSHOptions {
                host: body.host.clone(),
                port: body.port,
                username: "".into(),
                allow_insecure_algos: None,
                auth: SSHTargetAuth::Password(SshTargetPasswordAuth {
                    password: "".to_string().into(),
                }),
            }),
            None,
        ));

        let fut = async move {
            let key = loop {
                match handles.event_rx.recv().await {
                    Some(RCEvent::HostKeyReceived(key)) => break key,
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
