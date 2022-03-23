#![feature(type_alias_impl_trait, let_else)]
mod client;
mod common;
mod compat;
pub mod helpers;
mod keys;
mod known_hosts;
mod server;

use crate::client::{RCCommand, RemoteClient};
use anyhow::Result;
use async_trait::async_trait;
pub use client::*;
pub use common::*;
pub use keys::*;
use russh_keys::PublicKeyBase64;
pub use server::run_server;
use std::fmt::Debug;
use std::net::SocketAddr;
use uuid::Uuid;
use warpgate_common::{ProtocolServer, Services, Target, TargetTestError};

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

    async fn test_target(self, target: Target) -> Result<(), TargetTestError> {
        let Some(ssh_options) = target.ssh else {
            return Err(TargetTestError::Misconfigured("Not an SSH target".to_owned()));
        };

        let mut handles =
            RemoteClient::create(Uuid::new_v4(), "test".to_owned(), self.services.clone());

        let _ = handles.command_tx.send(RCCommand::Connect(ssh_options));

        while let Some(event) = handles.event_rx.recv().await {
            match event {
                RCEvent::ConnectionError(err) => {
                    if let ConnectionError::HostKeyMismatch {
                        ref received_key_type,
                        ref received_key_base64,
                        ref known_key_type,
                        ref known_key_base64,
                    } = err
                    {
                        println!("\n");
                        println!("Stored key   ({}): {}", known_key_type, known_key_base64);
                        println!(
                            "Received key ({}): {}",
                            received_key_type, received_key_base64
                        );
                        println!("Host key doesn't match the stored one.");
                        println!("If you know that the key is correct (e.g. it has been changed),");
                        println!("you can remove the old key in the Warpgate management UI and try again");
                    }
                    return Err(TargetTestError::ConnectionError(format!("{:?}", err)));
                }
                RCEvent::AuthError => {
                    return Err(TargetTestError::AuthenticationError);
                }
                RCEvent::HostKeyUnknown(key, reply) => {
                    println!("\nHost key ({}): {}", key.name(), key.public_key_base64());
                    println!("There is no trusted {} key for this host.", key.name());
                    if dialoguer::Confirm::new()
                        .with_prompt("Trust this key?")
                        .interact()?
                    {
                        let _ = reply.send(true);
                    } else {
                        let _ = reply.send(false);
                    }
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
