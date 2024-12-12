#![feature(type_alias_impl_trait, try_blocks)]
mod client;
mod common;
mod compat;
mod keys;
mod known_hosts;
mod server;
use std::fmt::Debug;
use std::net::SocketAddr;

use anyhow::Result;
use async_trait::async_trait;
pub use client::*;
pub use common::*;
pub use keys::*;
pub use server::run_server;
use uuid::Uuid;
use warpgate_common::{ProtocolName, SshHostKeyVerificationMode, Target, TargetOptions};
use warpgate_core::{ProtocolServer, Services, TargetTestError};

pub static PROTOCOL_NAME: ProtocolName = "SSH";

#[derive(Clone)]
pub struct SSHProtocolServer {
    services: Services,
}

impl SSHProtocolServer {
    pub async fn new(services: &Services) -> Result<Self> {
        let config = services.config.lock().await;
        generate_host_keys(&config)?;
        generate_client_keys(&config)?;
        Ok(SSHProtocolServer {
            services: services.clone(),
        })
    }
}

#[async_trait]
impl ProtocolServer for SSHProtocolServer {
    async fn run(self, address: SocketAddr) -> Result<()> {
        run_server(self.services, address).await
    }

    async fn test_target(&self, target: Target) -> Result<(), TargetTestError> {
        let TargetOptions::Ssh(ssh_options) = target.options else {
            return Err(TargetTestError::Misconfigured(
                "Not an SSH target".to_owned(),
            ));
        };

        let mut handles = RemoteClient::create(Uuid::new_v4(), self.services.clone())?;

        let _ = handles
            .command_tx
            .send((RCCommand::Connect(ssh_options), None));

        while let Some(event) = handles.event_rx.recv().await {
            match event {
                RCEvent::HostKeyUnknown(key, reply) => {
                    println!(
                        "\nHost key ({}): {}",
                        key.algorithm(),
                        key.to_openssh()
                            .map_err(|e| TargetTestError::ConnectionError(format!(
                                "ssh_key: {e:?}"
                            )))?
                    );
                    println!("There is no trusted {} key for this host.", key.algorithm());

                    match self
                        .services
                        .config
                        .lock()
                        .await
                        .store
                        .ssh
                        .host_key_verification
                    {
                        SshHostKeyVerificationMode::AutoAccept => {
                            let _ = reply.send(true);
                        }
                        SshHostKeyVerificationMode::AutoReject => {
                            let _ = reply.send(false);
                        }
                        SshHostKeyVerificationMode::Prompt => {
                            if dialoguer::Confirm::new()
                                .with_prompt("Trust this key?")
                                .interact()?
                            {
                                let _ = reply.send(true);
                            } else {
                                let _ = reply.send(false);
                            }
                        }
                    }
                }
                RCEvent::HostKeyReceived(_) => (),
                RCEvent::ConnectionError(err) => {
                    if let ConnectionError::HostKeyMismatch {
                        ref received_key_type,
                        ref received_key_base64,
                        ref known_key_type,
                        ref known_key_base64,
                    } = err
                    {
                        println!("\n");
                        println!("Stored key   ({known_key_type}): {known_key_base64}");
                        println!("Received key ({received_key_type}): {received_key_base64}");
                        println!("Host key doesn't match the stored one.");
                        println!("If you know that the key is correct (e.g. it has been changed),");
                        println!("you can remove the old key in the Warpgate management UI and try again");
                    }
                    return Err(TargetTestError::ConnectionError(format!("{err:?}")));
                }
                RCEvent::State(state) => match state {
                    RCState::Connected => {
                        return Ok(());
                    }
                    RCState::Disconnected => {
                        return Err(TargetTestError::ConnectionError(
                            "Connection failed".to_owned(),
                        ));
                    }
                    _ => {}
                },
                _ => {}
            }
        }

        Ok(())
    }
}

impl Debug for SSHProtocolServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SSHProtocolServer")
    }
}
