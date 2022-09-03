use std::pin::Pin;

use futures::FutureExt;
use russh::client::{Msg, Session};
use russh::Channel;
use russh_keys::key::PublicKey;
use russh_keys::PublicKeyBase64;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot;
use tracing::*;
use warpgate_common::{SessionId, TargetSSHOptions};
use warpgate_core::Services;

use crate::known_hosts::{KnownHostValidationResult, KnownHosts};
use crate::{ConnectionError, ForwardedTcpIpParams};

#[derive(Debug)]
pub enum ClientHandlerEvent {
    HostKeyReceived(PublicKey),
    HostKeyUnknown(PublicKey, oneshot::Sender<bool>),
    ForwardedTcpIp(Channel<Msg>, ForwardedTcpIpParams),
    X11(Channel<Msg>, String, u32),
    Disconnect,
}

pub struct ClientHandler {
    pub ssh_options: TargetSSHOptions,
    pub event_tx: UnboundedSender<ClientHandlerEvent>,
    pub services: Services,
    pub session_id: SessionId,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientHandlerError {
    #[error("Connection error")]
    ConnectionError(ConnectionError),

    #[error("SSH")]
    Ssh(#[from] russh::Error),

    #[error("Internal error")]
    Internal,
}

impl russh::client::Handler for ClientHandler {
    type Error = ClientHandlerError;
    type FutureUnit = Pin<
        Box<dyn core::future::Future<Output = Result<(Self, Session), ClientHandlerError>> + Send>,
    >;
    type FutureBool = Pin<
        Box<dyn core::future::Future<Output = Result<(Self, bool), ClientHandlerError>> + Send>,
    >;

    fn finished_bool(self, b: bool) -> Self::FutureBool {
        async move { Ok((self, b)) }.boxed()
    }

    fn finished(self, session: Session) -> Self::FutureUnit {
        async move { Ok((self, session)) }.boxed()
    }

    fn check_server_key(self, server_public_key: &PublicKey) -> Self::FutureBool {
        let mut known_hosts = KnownHosts::new(&self.services.db);
        let server_public_key = server_public_key.clone();
        async move {
            self.event_tx
                .send(ClientHandlerEvent::HostKeyReceived(
                    server_public_key.clone(),
                ))
                .map_err(|_| ClientHandlerError::ConnectionError(ConnectionError::Internal))?;
            match known_hosts
                .validate(
                    &self.ssh_options.host,
                    self.ssh_options.port,
                    &server_public_key,
                )
                .await
            {
                Ok(KnownHostValidationResult::Valid) => Ok((self, true)),
                Ok(KnownHostValidationResult::Invalid {
                    key_type,
                    key_base64,
                }) => {
                    warn!(session=%self.session_id, "Host key is invalid!");
                    return Err(ClientHandlerError::ConnectionError(
                        ConnectionError::HostKeyMismatch {
                            received_key_type: server_public_key.name().to_owned(),
                            received_key_base64: server_public_key.public_key_base64(),
                            known_key_type: key_type,
                            known_key_base64: key_base64,
                        },
                    ));
                }
                Ok(KnownHostValidationResult::Unknown) => {
                    warn!(session=%self.session_id, "Host key is unknown");

                    let (tx, rx) = oneshot::channel();
                    self.event_tx
                        .send(ClientHandlerEvent::HostKeyUnknown(
                            server_public_key.clone(),
                            tx,
                        ))
                        .map_err(|_| ClientHandlerError::Internal)?;
                    let accepted = rx.await.map_err(|_| ClientHandlerError::Internal)?;
                    if accepted {
                        if let Err(error) = known_hosts
                            .trust(
                                &self.ssh_options.host,
                                self.ssh_options.port,
                                &server_public_key,
                            )
                            .await
                        {
                            error!(?error, session=%self.session_id, "Failed to save host key");
                        }
                        Ok((self, true))
                    } else {
                        Ok((self, false))
                    }
                }
                Err(error) => {
                    error!(?error, session=%self.session_id, "Failed to verify the host key");
                    Err(ClientHandlerError::Internal)
                }
            }
        }
        .boxed()
    }

    fn server_channel_open_forwarded_tcpip(
        self,
        channel: Channel<Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        session: Session,
    ) -> Self::FutureUnit {
        let connected_address = connected_address.to_string();
        let originator_address = originator_address.to_string();
        async move {
            let _ = self.event_tx.send(ClientHandlerEvent::ForwardedTcpIp(
                channel,
                ForwardedTcpIpParams {
                    connected_address,
                    connected_port,
                    originator_address,
                    originator_port,
                },
            ));
            Ok((self, session))
        }
        .boxed()
    }

    fn server_channel_open_x11(
        self,
        channel: Channel<Msg>,
        originator_address: &str,
        originator_port: u32,
        session: Session,
    ) -> Self::FutureUnit {
        let originator_address = originator_address.to_string();
        async move {
            let _ = self.event_tx.send(ClientHandlerEvent::X11(
                channel,
                originator_address,
                originator_port,
            ));
            Ok((self, session))
        }
        .boxed()
    }
}

impl Drop for ClientHandler {
    fn drop(&mut self) {
        let _ = self.event_tx.send(ClientHandlerEvent::Disconnect);
        debug!(session=%self.session_id, "Dropped");
    }
}
