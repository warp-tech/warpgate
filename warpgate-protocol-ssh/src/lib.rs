#![feature(type_alias_impl_trait, let_else)]
mod client;
mod common;
mod compat;
mod server;
use crate::client::{RCCommand, RemoteClient};
use anyhow::Result;
use async_trait::async_trait;
pub use client::*;
pub use common::*;
pub use server::run_server;
use std::fmt::Debug;
use std::net::{SocketAddr, ToSocketAddrs};
use uuid::Uuid;
use warpgate_common::{ProtocolServer, Services, Target, TargetTestError};

#[derive(Clone)]
pub struct SSHProtocolServer {
    services: Services,
}

impl SSHProtocolServer {
    pub fn new(services: &Services) -> Self {
        SSHProtocolServer {
            services: services.clone(),
        }
    }
}

#[async_trait]
impl ProtocolServer for SSHProtocolServer {
    async fn run(self, address: SocketAddr) -> Result<()> {
        run_server(self.services, address).await
    }

    async fn test_target(self, target: Target) -> Result<(), TargetTestError> {
        let mut handles = RemoteClient::create(Uuid::new_v4(), "test".to_owned());
        let address_str = format!("{}:{}", target.host, target.port);
        let _ = handles.command_tx.send(RCCommand::Connect(
            address_str
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| TargetTestError::Unreachable)?
        ));

        loop {
            let Some(event) = handles.event_rx.recv().await else {
                break;
            };
            match event {
                RCEvent::ConnectionError(err) => {
                    return Err(TargetTestError::ConnectionError(err));
                }
                RCEvent::AuthError => {
                    return Err(TargetTestError::AuthenticationError);
                }
                RCEvent::State(state) => {
                    match state {
                        RCState::Connected => {
                            return Ok(());
                        }
                        RCState::Disconnected => {
                            return Err(TargetTestError::Unreachable);
                        }
                        _ => {}
                    }
                }
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
