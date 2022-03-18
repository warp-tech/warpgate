mod channel_direct_tcpip;
mod channel_session;
mod handler;
use self::handler::ClientHandlerEvent;
use super::{ChannelOperation, DirectTCPIPParams, ServerChannelId};
use anyhow::{Context, Result};
use bytes::Bytes;
use channel_direct_tcpip::DirectTCPIPChannel;
use channel_session::SessionChannel;
use futures::future::{Fuse, OptionFuture};
use futures::FutureExt;
use handler::ClientHandler;
use russh::client::Handle;
use russh::Sig;
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

#[derive(Clone, Debug)]
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
    ConnectionError(String),
    AuthError,
    Done,
}

#[derive(Debug)]
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

pub struct RemoteClient {
    id: SessionId,
    rx: UnboundedReceiver<RCCommand>,
    tx: UnboundedSender<RCEvent>,
    session: Option<Arc<Mutex<Handle<ClientHandler>>>>,
    channel_pipes: Arc<Mutex<HashMap<ServerChannelId, UnboundedSender<ChannelOperation>>>>,
    pending_ops: Vec<(ServerChannelId, ChannelOperation)>,
    state: RCState,
    client_handler_rx: Option<UnboundedReceiver<ClientHandlerEvent>>,
    abort_rx: Option<Fuse<oneshot::Receiver<()>>>,
    child_tasks: Vec<JoinHandle<Result<()>>>,
    session_tag: String,
    services: Services,
}

pub struct RemoteClientHandles {
    pub event_rx: UnboundedReceiver<RCEvent>,
    pub command_tx: UnboundedSender<RCCommand>,
    pub abort_tx: Option<oneshot::Sender<()>>,
}

impl RemoteClient {
    pub fn create(id: SessionId, session_tag: String, services: Services) -> RemoteClientHandles {
        let (event_tx, event_rx) = unbounded_channel();
        let (command_tx, command_rx) = unbounded_channel();
        let (abort_tx, abort_rx) = oneshot::channel();

        let this = Self {
            id,
            rx: command_rx,
            tx: event_tx,
            session: None,
            channel_pipes: Arc::new(Mutex::new(HashMap::new())),
            pending_ops: vec![],
            state: RCState::NotInitialized,
            client_handler_rx: None,
            abort_rx: Some(abort_rx.fuse()),
            child_tasks: vec![],
            session_tag,
            services,
        };
        this.start();
        RemoteClientHandles {
            event_rx,
            command_tx,
            abort_tx: Some(abort_tx),
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
                        cmd = self.rx.recv() => {
                            match cmd {
                                Some(RCCommand::Connect(options)) => match self.connect(options).await {
                                    Ok(_) => {
                                        self.set_state(RCState::Connected)?;
                                        let ops = self.pending_ops.drain(..).collect::<Vec<(ServerChannelId, ChannelOperation)>>();
                                        for (id, op) in ops {
                                            self.apply_channel_op(id, op).await?;
                                        }
                                    }
                                    Err(e) => {
                                        self.set_disconnected();
                                        debug!(session=%self.session_tag, "Connect error: {}", e);
                                        break
                                    }
                                },
                                Some(RCCommand::Channel(ch, op)) => {
                                    self.apply_channel_op(ch, op).await?;
                                }
                                Some(RCCommand::Disconnect) => {
                                    self.disconnect().await?;
                                    break
                                }
                                None => {
                                    break
                                }
                            }
                        }
                        Some(client_event) = OptionFuture::from(self.client_handler_rx.as_mut().map(|x| x.recv())) => {
                            debug!(session=%self.session_tag, "Client handler event: {:?}", client_event);
                            match client_event {
                                Some(ClientHandlerEvent::Disconnect) => {
                                    self._on_disconnect().await?;
                                }
                                None => {
                                    self.client_handler_rx = None
                                }
                            }
                        }
                        Some(Ok(_)) = OptionFuture::from(self.abort_rx.as_mut()) => {
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

    async fn connect(&mut self, ssh_options: TargetSSHOptions) -> Result<()> {
        let address_str = format!("{}:{}", ssh_options.host, ssh_options.port);
        let address = match address_str
            .to_socket_addrs()
            .map_err(|e| anyhow::anyhow!("{}", e))
            .and_then(|mut x| {
                x.next()
                    .ok_or_else(|| anyhow::anyhow!("Cannot resolve address"))
            }) {
            Ok(address) => address,
            Err(error) => {
                let _ = self
                    .tx
                    .send(RCEvent::ConnectionError(format!("{:?}", error)));
                error!(?error, "Cannot resolve target address");
                self.set_disconnected();
                return Err(error);
            }
        };

        info!(?address, username=?ssh_options.username, session=%self.session_tag, "Connecting");
        let client_key = load_secret_key("/Users/eugene/.ssh/id_rsa", None)
            .with_context(|| "load_secret_key()")?;
        let client_key = Arc::new(client_key);
        let config = russh::client::Config {
            ..Default::default()
        };
        let config = Arc::new(config);

        let (tx, rx) = unbounded_channel();
        let handler = ClientHandler {
            ssh_options: ssh_options.clone(),
            tx,
            services: self.services.clone(),
        };
        self.client_handler_rx = Some(rx);

        // self.tx.send(RCEvent::Output(Bytes::from(
        //     "Connecting now...\r\n".as_bytes(),
        // )))?;

        let fut_connect = russh::client::connect(config, address, handler);

        tokio::select! {
            Some(Ok(_)) = OptionFuture::from(self.abort_rx.as_mut()) => {
                info!(session=%self.session_tag, "Abort requested");
                self.set_disconnected();
                anyhow::bail!("Aborted");
            }
            session = fut_connect => {
                if let Err(err) = session {
                    self.tx.send(RCEvent::ConnectionError(format!("{:?}", err)))?;
                    error!(error=?err, session=%self.session_tag, "Connection error");
                    anyhow::bail!("Error connecting: {}", err);
                }

                let mut session = session.with_context(|| "connect()")?;

                let auth_result = session
                    // .authenticate_password(ssh_options.username, "syslink")
                    .authenticate_publickey(ssh_options.username, client_key)
                    .await
                    .with_context(|| "authenticate()")?;
                if !auth_result {
                    self.tx.send(RCEvent::AuthError)?;
                    error!(session=%self.session_tag, "Auth rejected");
                    let _ = session
                        .disconnect(russh::Disconnect::ByApplication, "", "")
                        .await;
                    anyhow::bail!("Auth rejected");
                }

                self.session = Some(Arc::new(Mutex::new(session)));

                info!(?address, session=%self.session_tag, "Connected");
                Ok(())
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
