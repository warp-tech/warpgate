mod channel_direct_tcpip;
mod channel_session;
mod handler;
use crate::client::handler::ClientHandlerError;

use self::handler::ClientHandlerEvent;
use super::{ChannelOperation, DirectTCPIPParams, ServerChannelId};
use anyhow::{Context, Result};
use bytes::Bytes;
use channel_direct_tcpip::DirectTCPIPChannel;
use channel_session::SessionChannel;
use futures::pin_mut;
use handler::ClientHandler;
use russh::client::Handle;
use russh::Sig;
use russh_keys::key::PublicKey;
use russh_keys::load_secret_key;
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinHandle;
use tracing::*;
use warpgate_common::{Services, SessionId, TargetSSHOptions};

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
    SSH(#[from] russh::Error),

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
    Output(ServerChannelId, Bytes),
    Success(ServerChannelId),
    Eof(ServerChannelId),
    Close(ServerChannelId),
    ExitStatus(ServerChannelId, u32),
    ExitSignal {
        channel: ServerChannelId,
        signal_name: Sig,
        core_dumped: bool,
        error_message: String,
        lang_tag: String,
    },
    ExtendedData {
        channel: ServerChannelId,
        data: Bytes,
        ext: u32,
    },
    ConnectionError(ConnectionError),
    AuthError,
    HostKeyReceived(PublicKey),
    HostKeyUnknown(PublicKey, oneshot::Sender<bool>),
    Done,
}

#[derive(Clone, Debug)]
pub enum RCCommand {
    Connect(TargetSSHOptions),
    Channel(ServerChannelId, ChannelOperation),
    Disconnect,
}

#[derive(Clone, Debug, PartialEq)]
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
    channel_pipes: Arc<Mutex<HashMap<ServerChannelId, UnboundedSender<ChannelOperation>>>>,
    pending_ops: Vec<(ServerChannelId, ChannelOperation)>,
    state: RCState,
    abort_rx: UnboundedReceiver<()>,
    inner_event_rx: UnboundedReceiver<InnerEvent>,
    inner_event_tx: UnboundedSender<InnerEvent>,
    child_tasks: Vec<JoinHandle<Result<()>>>,
    services: Services,
    session_tag: String,
}

pub struct RemoteClientHandles {
    pub event_rx: UnboundedReceiver<RCEvent>,
    pub command_tx: UnboundedSender<RCCommand>,
    pub abort_tx: UnboundedSender<()>,
}

impl RemoteClient {
    pub fn create(id: SessionId, session_tag: String, services: Services) -> RemoteClientHandles {
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
            session_tag,
            services,
            abort_rx,
        };

        tokio::spawn({
            async move {
                while let Some(e) = command_rx.recv().await {
                    inner_event_tx.send(InnerEvent::RCCommand(e))?
                }
                Ok::<(), anyhow::Error>(())
            }
        });

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

    async fn apply_channel_op(
        &mut self,
        channel_id: ServerChannelId,
        op: ChannelOperation,
    ) -> Result<()> {
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
                        debug!(channel=%channel_id, session=%self.session_tag, "operation for unknown channel")
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
                                                let ops = self.pending_ops.drain(..).collect::<Vec<(ServerChannelId, ChannelOperation)>>();
                                                for (id, op) in ops {
                                                    self.apply_channel_op(id, op).await?;
                                                }
                                            }
                                            Err(e) => {
                                                debug!(session=%self.session_tag, "Connect error: {}", e);
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
                                    debug!(session=%self.session_tag, "Client handler event: {:?}", client_event);
                                    match client_event {
                                        ClientHandlerEvent::Disconnect => {
                                            self._on_disconnect().await?;
                                        }
                                        event => {
                                            error!(session=%self.session_tag, ?event, "Unhandled client handler event");
                                        },
                                    }
                                }
                            }
                        }
                        Some(_) = self.abort_rx.recv() => {
                            debug!(session=%self.session_tag, "Abort requested");
                            self.disconnect().await?;
                            break
                        }
                    };
                }
                Ok::<(), anyhow::Error>(())
            }
            .await
            .map_err(|error| {
                error!(?error, session=%self.session_tag, "error in command loop");
                anyhow::anyhow!("Error in command loop: {error}")
            })?;
            debug!(session=%self.session_tag, "No more commmands");
            Ok::<(), anyhow::Error>(())
        });
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

        info!(?address, username=?ssh_options.username, session=%self.session_tag, "Connecting");
        let client_key =
            load_secret_key("/Users/eugene/.ssh/id_rsa", None).map_err(ConnectionError::Key)?;
        let client_key = Arc::new(client_key);
        let config = russh::client::Config {
            ..Default::default()
        };
        let config = Arc::new(config);

        let (event_tx, mut event_rx) = unbounded_channel();
        let handler = ClientHandler {
            ssh_options: ssh_options.clone(),
            event_tx,
            services: self.services.clone(),
            session_tag: self.session_tag.clone(),
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
                    info!(session=%self.session_tag, "Abort requested");
                    self.set_disconnected();
                    return Err(ConnectionError::Aborted)
                }
                session = &mut fut_connect => {
                    if let Err(error) = session {
                        let connection_error = match error {
                            ClientHandlerError::ConnectionError(e) => e,
                            ClientHandlerError::Ssh(e) => ConnectionError::SSH(e),
                            ClientHandlerError::Internal => ConnectionError::Internal,
                        };
                        error!(error=?connection_error, session=%self.session_tag, "Connection error");
                        return Err(connection_error);
                    }

                    #[allow(clippy::unwrap_used)]
                    let mut session = session.unwrap();

                    let auth_result = session
                        // .authenticate_password(ssh_options.username, "syslink")
                        .authenticate_publickey(ssh_options.username, client_key)
                        .await?;
                    if !auth_result {
                        let _ = self.tx.send(RCEvent::AuthError);
                        error!(session=%self.session_tag, "Auth rejected");
                        let _ = session
                            .disconnect(russh::Disconnect::ByApplication, "", "")
                            .await;
                        return Err(ConnectionError::Authentication);
                    }

                    self.session = Some(Arc::new(Mutex::new(session)));

                    info!(?address, session=%self.session_tag, "Connected");

                    tokio::spawn({
                        let inner_event_tx = self.inner_event_tx.clone();
                        async move {
                            while let Some(e) = event_rx.recv().await {
                                info!("{:?}", e);
                                inner_event_tx.send(InnerEvent::ClientHandlerEvent(e))?
                            }
                            Ok::<(), anyhow::Error>(())
                        }
                    });

                    return Ok(())
                }
            }
        }
    }

    async fn open_shell(&mut self, channel_id: ServerChannelId) -> Result<()> {
        if let Some(session) = &self.session {
            let mut session = session.lock().await;
            let channel = session.channel_open_session().await?;

            let (tx, rx) = unbounded_channel();
            self.channel_pipes.lock().await.insert(channel_id, tx);

            let channel = SessionChannel::new(
                channel,
                channel_id,
                rx,
                self.tx.clone(),
                self.session_tag.clone(),
            );
            self.child_tasks.push(
                tokio::task::Builder::new()
                    .name(&format!("SSH {} {:?} ops", self.id, channel_id.0))
                    .spawn(channel.run()),
            );
        }
        Ok(())
    }

    async fn open_direct_tcpip(
        &mut self,
        channel_id: ServerChannelId,
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

            let channel = DirectTCPIPChannel::new(
                channel,
                channel_id,
                rx,
                self.tx.clone(),
                self.session_tag.clone(),
            );
            self.child_tasks.push(
                tokio::task::Builder::new()
                    .name(&format!("SSH {} {:?} ops", self.id, channel_id.0))
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
            let _ = task.abort();
        }
        info!(session=%self.session_tag, "Closed connection");
        debug!(session=%self.session_tag, "Dropped");
    }
}
