mod channel_direct_tcpip;
mod channel_session;
mod handler;
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use channel_direct_tcpip::DirectTCPIPChannel;
use channel_session::SessionChannel;
use futures::pin_mut;
use handler::ClientHandler;
use russh::client::Handle;
use russh::{Preferred, Sig};
use russh_keys::key::{self, PublicKey};
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinHandle;
use tracing::*;
use uuid::Uuid;
use warpgate_common::{SSHTargetAuth, SessionId, TargetSSHOptions};
use warpgate_core::Services;

use self::handler::ClientHandlerEvent;
use super::{ChannelOperation, DirectTCPIPParams};
use crate::client::handler::ClientHandlerError;
use crate::helpers::PublicKeyAsOpenSSH;
use crate::keys::load_client_keys;

#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error("Host key mismatch")]
    HostKeyMismatch {
        received_key_type: String,
        received_key_base64: String,
        known_key_type: String,
        known_key_base64: String,
    },

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Key(#[from] russh_keys::Error),

    #[error(transparent)]
    Ssh(#[from] russh::Error),

    #[error("Could not resolve address")]
    Resolve,

    #[error("Internal error")]
    Internal,

    #[error("Aborted")]
    Aborted,

    #[error("Authentication failed")]
    Authentication,
}

#[derive(Debug)]
pub enum RCEvent {
    State(RCState),
    Output(Uuid, Bytes),
    Success(Uuid),
    Eof(Uuid),
    Close(Uuid),
    ExitStatus(Uuid, u32),
    ExitSignal {
        channel: Uuid,
        signal_name: Sig,
        core_dumped: bool,
        error_message: String,
        lang_tag: String,
    },
    ExtendedData {
        channel: Uuid,
        data: Bytes,
        ext: u32,
    },
    ConnectionError(ConnectionError),
    HostKeyReceived(PublicKey),
    HostKeyUnknown(PublicKey, oneshot::Sender<bool>),
    // ForwardedTCPIP(Uuid, DirectTCPIPParams),
    Done,
}

#[derive(Clone, Debug)]
pub enum RCCommand {
    Connect(TargetSSHOptions),
    Channel(Uuid, ChannelOperation),
    // ForwardTCPIP(String, u32),
    // CancelTCPIPForward(String, u32),
    Disconnect,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RCState {
    NotInitialized,
    Connecting,
    Connected,
    Disconnected,
}

#[derive(Debug)]
enum InnerEvent {
    RCCommand(RCCommand),
    ClientHandlerEvent(ClientHandlerEvent),
}

pub struct RemoteClient {
    id: SessionId,
    tx: UnboundedSender<RCEvent>,
    session: Option<Arc<Mutex<Handle<ClientHandler>>>>,
    channel_pipes: Arc<Mutex<HashMap<Uuid, UnboundedSender<ChannelOperation>>>>,
    pending_ops: Vec<(Uuid, ChannelOperation)>,
    state: RCState,
    abort_rx: UnboundedReceiver<()>,
    inner_event_rx: UnboundedReceiver<InnerEvent>,
    inner_event_tx: UnboundedSender<InnerEvent>,
    child_tasks: Vec<JoinHandle<Result<()>>>,
    services: Services,
}

pub struct RemoteClientHandles {
    pub event_rx: UnboundedReceiver<RCEvent>,
    pub command_tx: UnboundedSender<RCCommand>,
    pub abort_tx: UnboundedSender<()>,
}

impl RemoteClient {
    pub fn create(id: SessionId, services: Services) -> RemoteClientHandles {
        let (event_tx, event_rx) = unbounded_channel();
        let (command_tx, mut command_rx) = unbounded_channel();
        let (abort_tx, abort_rx) = unbounded_channel();

        let (inner_event_tx, inner_event_rx) = unbounded_channel();

        let this = Self {
            id,
            tx: event_tx,
            session: None,
            channel_pipes: Arc::new(Mutex::new(HashMap::new())),
            pending_ops: vec![],
            state: RCState::NotInitialized,
            inner_event_rx,
            inner_event_tx: inner_event_tx.clone(),
            child_tasks: vec![],
            services,
            abort_rx,
        };

        tokio::spawn(
            {
                async move {
                    while let Some(e) = command_rx.recv().await {
                        inner_event_tx.send(InnerEvent::RCCommand(e))?
                    }
                    Ok::<(), anyhow::Error>(())
                }
            }
            .instrument(Span::current()),
        );

        this.start();

        RemoteClientHandles {
            event_rx,
            command_tx,
            abort_tx,
        }
    }

    fn set_disconnected(&mut self) {
        self.session = None;
        for (id, op) in self.pending_ops.drain(..) {
            if let ChannelOperation::OpenShell = op {
                let _ = self.tx.send(RCEvent::Close(id));
            }
            if let ChannelOperation::OpenDirectTCPIP { .. } = op {
                let _ = self.tx.send(RCEvent::Close(id));
            }
        }
        let _ = self.set_state(RCState::Disconnected);
        let _ = self.tx.send(RCEvent::Done);
    }

    fn set_state(&mut self, state: RCState) -> Result<()> {
        self.state = state.clone();
        self.tx.send(RCEvent::State(state))?;
        Ok(())
    }

    // fn map_channel(&self, ch: &ChannelId) -> Result<Uuid> {
    //     self.channel_map
    //         .get_by_left(ch)
    //         .cloned()
    //         .ok_or_else(|| anyhow::anyhow!("Channel not known"))
    // }

    // fn map_channel_reverse(&self, ch: &Uuid) -> Result<ChannelId> {
    //     self.channel_map
    //         .get_by_right(ch)
    //         .cloned()
    //         .ok_or_else(|| anyhow::anyhow!("Channel not known"))
    // }

    async fn apply_channel_op(&mut self, channel_id: Uuid, op: ChannelOperation) -> Result<()> {
        if self.state != RCState::Connected {
            self.pending_ops.push((channel_id, op));
            return Ok(());
        }

        match op {
            ChannelOperation::OpenShell => {
                self.open_shell(channel_id)
                    .await
                    .context("failed to open shell")?;
            }
            ChannelOperation::OpenDirectTCPIP(params) => {
                self.open_direct_tcpip(channel_id, params)
                    .await
                    .context("failed to open direct tcp/ip channel")?;
            }
            op => {
                let mut channel_pipes = self.channel_pipes.lock().await;
                match channel_pipes.get(&channel_id) {
                    Some(tx) => match tx.send(op) {
                        Ok(_) => {}
                        Err(SendError(_)) => {
                            channel_pipes.remove(&channel_id);
                        }
                    },
                    None => {
                        debug!(channel=%channel_id, "operation for unknown channel")
                    }
                }
            }
        }
        Ok(())
    }

    pub fn start(mut self) {
        let name = format!("SSH {} client commands", self.id);
        tokio::task::Builder::new().name(&name).spawn(async move {
            async {
                loop {
                    tokio::select! {
                        Some(event) = self.inner_event_rx.recv() => {
                            match event {
                                InnerEvent::RCCommand(cmd) => {
                                    match cmd {
                                        RCCommand::Connect(options) => match self.connect(options).await {
                                            Ok(_) => {
                                                self.set_state(RCState::Connected)?;
                                                let ops = self.pending_ops.drain(..).collect::<Vec<_>>();
                                                for (id, op) in ops {
                                                    self.apply_channel_op(id, op).await?;
                                                }
                                                // let forwards = self.pending_forwards.drain(..).collect::<Vec<_>>();
                                                // for (address, port) in forwards {
                                                //     self.tcpip_forward(address, port).await?;
                                                // }
                                            }
                                            Err(e) => {
                                                debug!("Connect error: {}", e);
                                                let _ = self.tx.send(RCEvent::ConnectionError(e));
                                                self.set_disconnected();
                                                break
                                            }
                                        },
                                        RCCommand::Channel(ch, op) => {
                                            self.apply_channel_op(ch, op).await?;
                                        }
                                        RCCommand::Disconnect => {
                                            self.disconnect().await?;
                                            break
                                        }
                                    }
                                }
                                InnerEvent::ClientHandlerEvent(client_event) => {
                                    debug!("Client handler event: {:?}", client_event);
                                    match client_event {
                                        ClientHandlerEvent::Disconnect => {
                                            self._on_disconnect().await?;
                                        }
                                        event => {
                                            error!(?event, "Unhandled client handler event");
                                        },
                                    }
                                }
                            }
                        }
                        Some(_) = self.abort_rx.recv() => {
                            debug!("Abort requested");
                            self.disconnect().await?;
                            break
                        }
                    };
                }
                Ok::<(), anyhow::Error>(())
            }
            .await
            .map_err(|error| {
                error!(?error, "error in command loop");
                anyhow::anyhow!("Error in command loop: {error}")
            })?;
            debug!("No more commmands");
            Ok::<(), anyhow::Error>(())
        }.instrument(Span::current()));
    }

    async fn connect(&mut self, ssh_options: TargetSSHOptions) -> Result<(), ConnectionError> {
        let address_str = format!("{}:{}", ssh_options.host, ssh_options.port);
        let address = match address_str
            .to_socket_addrs()
            .map_err(ConnectionError::Io)
            .and_then(|mut x| x.next().ok_or(ConnectionError::Resolve))
        {
            Ok(address) => address,
            Err(error) => {
                error!(?error, "Cannot resolve target address");
                self.set_disconnected();
                return Err(error);
            }
        };

        info!(?address, username = &ssh_options.username[..], "Connecting");
        let config = russh::client::Config {
            preferred: Preferred {
                key: &[
                    key::ED25519,
                    key::RSA_SHA2_256,
                    key::RSA_SHA2_512,
                    key::SSH_RSA,
                ],
                ..<_>::default()
            },
            ..Default::default()
        };
        let config = Arc::new(config);

        let (event_tx, mut event_rx) = unbounded_channel();
        let handler = ClientHandler {
            ssh_options: ssh_options.clone(),
            event_tx,
            services: self.services.clone(),
            session_id: self.id,
        };

        let fut_connect = russh::client::connect(config, address, handler);
        pin_mut!(fut_connect);

        loop {
            tokio::select! {
                Some(event) = event_rx.recv() => {
                    match event {
                        ClientHandlerEvent::HostKeyReceived(key) => {
                            self.tx.send(RCEvent::HostKeyReceived(key)).map_err(|_| ConnectionError::Internal)?;
                        }
                        ClientHandlerEvent::HostKeyUnknown(key, reply) => {
                            self.tx.send(RCEvent::HostKeyUnknown(key, reply)).map_err(|_| ConnectionError::Internal)?;
                        }
                        _ => {}
                    }
                }
                Some(_) = self.abort_rx.recv() => {
                    info!("Abort requested");
                    self.set_disconnected();
                    return Err(ConnectionError::Aborted)
                }
                session = &mut fut_connect => {
                    let mut session = match session {
                        Ok(session) => session,
                        Err(error) => {
                            let connection_error = match error {
                                ClientHandlerError::ConnectionError(e) => e,
                                ClientHandlerError::Ssh(e) => ConnectionError::Ssh(e),
                                ClientHandlerError::Internal => ConnectionError::Internal,
                            };
                            error!(error=?connection_error, "Connection error");
                            return Err(connection_error);
                        }
                    };

                    let mut auth_result = false;
                    match ssh_options.auth {
                        SSHTargetAuth::Password(auth) => {
                            auth_result = session
                                .authenticate_password(ssh_options.username.clone(), auth.password.expose_secret())
                                .await?;
                            if auth_result {
                                debug!(username=&ssh_options.username[..], "Authenticated with password");
                            }
                        }
                        SSHTargetAuth::PublicKey(_) => {
                            #[allow(clippy::explicit_auto_deref)]
                            let keys = load_client_keys(&*self.services.config.lock().await)?;
                            for key in keys.into_iter() {
                                let key_str = key.as_openssh();
                                auth_result = session
                                    .authenticate_publickey(ssh_options.username.clone(), Arc::new(key))
                                    .await?;
                                if auth_result {
                                    debug!(username=&ssh_options.username[..], key=%key_str, "Authenticated with key");
                                    break;
                                }
                            }
                        }
                    }

                    if !auth_result {
                        error!("Auth rejected");
                        let _ = session
                            .disconnect(russh::Disconnect::ByApplication, "", "")
                            .await;
                        return Err(ConnectionError::Authentication);
                    }

                    self.session = Some(Arc::new(Mutex::new(session)));

                    info!(?address, "Connected");

                    tokio::spawn({
                        let inner_event_tx = self.inner_event_tx.clone();
                        async move {
                            while let Some(e) = event_rx.recv().await {
                                info!("{:?}", e);
                                inner_event_tx.send(InnerEvent::ClientHandlerEvent(e))?
                            }
                            Ok::<(), anyhow::Error>(())
                        }
                    }.instrument(Span::current()));

                    return Ok(())
                }
            }
        }
    }

    async fn open_shell(&mut self, channel_id: Uuid) -> Result<()> {
        if let Some(session) = &self.session {
            let mut session = session.lock().await;
            let channel = session.channel_open_session().await?;

            let (tx, rx) = unbounded_channel();
            self.channel_pipes.lock().await.insert(channel_id, tx);

            let channel = SessionChannel::new(channel, channel_id, rx, self.tx.clone(), self.id);
            self.child_tasks.push(
                tokio::task::Builder::new()
                    .name(&format!("SSH {} {:?} ops", self.id, channel_id))
                    .spawn(channel.run()),
            );
        }
        Ok(())
    }

    async fn open_direct_tcpip(
        &mut self,
        channel_id: Uuid,
        params: DirectTCPIPParams,
    ) -> Result<()> {
        if let Some(session) = &self.session {
            let mut session = session.lock().await;
            let channel = session
                .channel_open_direct_tcpip(
                    params.host_to_connect,
                    params.port_to_connect,
                    params.originator_address,
                    params.originator_port,
                )
                .await?;

            let (tx, rx) = unbounded_channel();
            self.channel_pipes.lock().await.insert(channel_id, tx);

            let channel =
                DirectTCPIPChannel::new(channel, channel_id, rx, self.tx.clone(), self.id);
            self.child_tasks.push(
                tokio::task::Builder::new()
                    .name(&format!("SSH {} {:?} ops", self.id, channel_id))
                    .spawn(channel.run()),
            );
        }
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        if let Some(session) = &mut self.session {
            let _ = session
                .lock()
                .await
                .disconnect(russh::Disconnect::ByApplication, "", "")
                .await;
            self.set_disconnected();
        }
        Ok(())
    }

    async fn _on_disconnect(&mut self) -> Result<()> {
        self.set_disconnected();
        Ok(())
    }
}

impl Drop for RemoteClient {
    fn drop(&mut self) {
        for task in self.child_tasks.drain(..) {
            task.abort();
        }
        info!("Closed connection");
        debug!("Dropped");
    }
}
