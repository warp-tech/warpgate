use std::pin::Pin;

use futures::FutureExt;
use russh::client::Session;
use russh_keys::key::PublicKey;
use tokio::sync::mpsc::UnboundedSender;
use tracing::*;
use warpgate_common::{Services, TargetSSHOptions};

use crate::known_hosts::{KnownHostValidationResult, KnownHosts};

pub struct ClientHandler {
    pub ssh_options: TargetSSHOptions,
    pub tx: UnboundedSender<ClientHandlerEvent>,
    pub services: Services,
}

#[derive(Debug)]
pub enum ClientHandlerEvent {
    Disconnect,
}

impl russh::client::Handler for ClientHandler {
    type Error = anyhow::Error;
    type FutureUnit = futures::future::Ready<Result<(Self, Session), anyhow::Error>>;
    type FutureBool =
        Pin<Box<dyn core::future::Future<Output = anyhow::Result<(Self, bool)>> + Send>>;

    fn finished_bool(self, b: bool) -> Self::FutureBool {
        async move { Ok((self, b)) }.boxed()
    }

    fn finished(self, session: Session) -> Self::FutureUnit {
        futures::future::ready(Ok((self, session)))
    }

    fn check_server_key(self, server_public_key: &PublicKey) -> Self::FutureBool {
        let mut known_hosts = KnownHosts::new(&self.services.db);
        let server_public_key = server_public_key.clone();
        async move {
            match known_hosts
                .validate(
                    &self.ssh_options.host,
                    self.ssh_options.port,
                    &server_public_key,
                )
                .await
            {
                Ok(KnownHostValidationResult::Valid) => Ok((self, true)),
                Ok(KnownHostValidationResult::Invalid) => {
                    warn!("Host key is invalid!");
                    Ok((self, false))
                }
                Ok(KnownHostValidationResult::Unknown) => {
                    warn!("Host key is unknown");
                    Ok((self, false))
                }
                Err(error) => {
                    error!(?error, "Failed to verify the host key");
                    Err(anyhow::Error::new(error))
                }
            }
        }
        .boxed()
    }
}

impl Drop for ClientHandler {
    fn drop(&mut self) {
        let _ = self.tx.send(ClientHandlerEvent::Disconnect);
        debug!("Dropped");
    }
}
