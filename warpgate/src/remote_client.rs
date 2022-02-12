use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use futures::future::{Fuse, OptionFuture};
use futures::FutureExt;
use std::any::Any;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::{sync::Arc, time::Duration};
use thrussh::client::{Channel, Handle, Session};
use thrussh::{ChannelId, Pty};
use thrussh_keys::key::PublicKey;
use thrussh_keys::load_secret_key;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{self, unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinHandle;
use tracing::*;

#[derive(Clone, Debug)]
pub enum RCEvent {
    State(RCState),
    Output(ServerChannelId, Bytes),
    Success(ServerChannelId),
    Eof(ServerChannelId),
    Close(ServerChannelId),
    ExitStatus(ServerChannelId, u32),
    Done,
}

#[derive(Clone, Debug)]
pub struct PtyRequest {
    pub term: String,
    pub col_width: u32,
    pub row_height: u32,
    pub pix_width: u32,
    pub pix_height: u32,
    pub modes: Vec<(Pty, u32)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Hash, Eq)]
pub struct ServerChannelId(pub ChannelId);

#[derive(Debug)]
pub enum ChannelOperation {
    OpenShell,
    RequestPty(PtyRequest),
    ResizePty(PtyRequest),
    RequestShell,
    Data(Bytes),
}

#[derive(Debug)]
pub enum RCCommand {
    Connect(SocketAddr),
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
    rx: UnboundedReceiver<RCCommand>,
    tx: UnboundedSender<RCEvent>,
    session: Option<Arc<Mutex<Handle<ClientHandler>>>>,
    channel_pipes: Arc<Mutex<HashMap<ServerChannelId, UnboundedSender<ChannelOperation>>>>,
    pending_ops: Vec<(ServerChannelId, ChannelOperation)>,
    state: RCState,
    client_handler_rx: Option<UnboundedReceiver<ClientHandlerEvent>>,
    abort_rx: Option<Fuse<oneshot::Receiver<()>>>,
    child_tasks: Vec<JoinHandle<Result<()>>>,
}

pub struct RemoteClientHandles {
    pub event_rx: UnboundedReceiver<RCEvent>,
    pub command_tx: UnboundedSender<RCCommand>,
    pub abort_tx: Option<oneshot::Sender<()>>,
}

impl RemoteClient {
    pub fn create() -> RemoteClientHandles {
        let (event_tx, mut event_rx) = unbounded_channel();
        let (command_tx, command_rx) = unbounded_channel();
        let (abort_tx, abort_rx) = oneshot::channel();

        let this = Self {
            rx: command_rx,
            tx: event_tx,
            session: None,
            channel_pipes: Arc::new(Mutex::new(HashMap::new())),
            pending_ops: vec![],
            state: RCState::NotInitialized,
            client_handler_rx: None,
            abort_rx: Some(abort_rx.fuse()),
            child_tasks: vec![],
        };
        this.start();
        return RemoteClientHandles {
            event_rx,
            command_tx,
            abort_tx: Some(abort_tx),
        };
    }

    fn set_disconnected(&mut self) {
        self.session = None;
        for (id, op) in self.pending_ops.drain(..).into_iter() {
            if let ChannelOperation::OpenShell = op {
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
            op => {
                let mut channel_pipes = self.channel_pipes.lock().await;
                match channel_pipes.get(&channel_id) {
                    Some(tx) => match tx.send(op) {
                        Ok(_) => {}
                        Err(SendError(_)) => {
                            channel_pipes.remove(&channel_id);
                        }
                    },
                    None => debug!(channel=?channel_id, "operation for unknown channel"),
                }
            }
        }
        Ok(())
    }

    pub fn start(mut self) {
        tokio::spawn(async move {
            async {
                loop {
                    tokio::select! {
                        cmd = self.rx.recv() => {
                            match cmd {
                                Some(RCCommand::Connect(address)) => match self.connect(address).await {
                                    Ok(_) => {
                                        self.set_state(RCState::Connected)?;
                                        let ops = self.pending_ops.drain(..).collect::<Vec<(ServerChannelId, ChannelOperation)>>();
                                        for (id, op) in ops {
                                            self.apply_channel_op(id, op).await?;
                                        }
                                    }
                                    Err(e) => {
                                        self.set_disconnected();
                                        debug!("connect error: {}", e);
                                    }
                                },
                                Some(RCCommand::Channel(ch, op)) => {
                                    self.apply_channel_op(ch, op).await?;
                                }
                                Some(RCCommand::Disconnect) => {
                                    self.disconnect().await?;
                                }
                                None => {
                                    break;
                                }
                            }
                        }
                        Some(client_event) = OptionFuture::from(self.client_handler_rx.as_mut().map(|x| x.recv())) => {
                            debug!("client handler event: {:?}", client_event);
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
            debug!("no more commmands");
            Ok::<(), anyhow::Error>(())
        });
    }

    async fn connect(&mut self, address: SocketAddr) -> Result<()> {
        debug!("connecting");
        let client_key = load_secret_key("/Users/eugene/.ssh/id_rsa", None)
            .with_context(|| "load_secret_key()")?;
        let client_key = Arc::new(client_key);
        let config = thrussh::client::Config {
            ..Default::default()
        };
        let config = Arc::new(config);
        // tokio::time::sleep(Duration::from_millis(5000)).await;

        let (tx, rx) = unbounded_channel();
        let handler = ClientHandler { tx };
        self.client_handler_rx = Some(rx);

        // self.tx.send(RCEvent::Output(Bytes::from(
        //     "Connecting now...\r\n".as_bytes(),
        // )))?;

        let fut_connect = thrussh::client::connect(config, address, handler);

        tokio::select! {
            Some(Ok(_)) = OptionFuture::from(self.abort_rx.as_mut()) => {
                debug!("Abort requested");
                self.set_disconnected();
                anyhow::bail!("Aborted");
            }
            session = fut_connect => {
                let mut session = session.with_context(|| "connect()")?;

                let auth_result = session
                    .authenticate_password("root", "syslink")
                    // .authenticate_publickey("root", client_key)
                    .await
                    .with_context(|| "authenticate()")?;
                if !auth_result {
                    debug!("auth failed");
                    let _ = session
                        .disconnect(thrussh::Disconnect::ByApplication, "", "")
                        .await;
                    anyhow::bail!("auth failed");
                }

                self.session = Some(Arc::new(Mutex::new(session)));

                debug!("done");
                Ok(())
            }
        }
    }

    async fn open_shell(&mut self, channel_id: ServerChannelId) -> Result<()> {
        if let Some(session) = &self.session {
            let mut session = session.lock().await;
            let mut channel = session.channel_open_session().await?;

            let (tx, mut rx) = unbounded_channel();
            self.channel_pipes.lock().await.insert(channel_id, tx);

            self.child_tasks.push(tokio::spawn({
                let tx = self.tx.clone();
                async move {
                    loop {
                        tokio::select! {
                            incoming_data = rx.recv() => {
                                match incoming_data {
                                    Some(ChannelOperation::Data(data)) => {
                                        channel.data(&*data).await.context("data")?;
                                    }
                                    Some(ChannelOperation::RequestPty(request)) => {
                                        channel.request_pty(
                                            true,
                                            &request.term,
                                            request.col_width,
                                            request.row_height,
                                            request.pix_width,
                                            request.pix_height,
                                            &request.modes,
                                        ).await.context("request_pty")?;
                                    }
                                    Some(ChannelOperation::ResizePty(request)) => {
                                        channel.window_change(
                                            request.col_width,
                                            request.row_height,
                                            request.pix_width,
                                            request.pix_height,
                                        ).await.context("resize_pty")?;
                                    },
                                    Some(ChannelOperation::RequestShell) => {
                                        channel.request_shell(true).await.context("request_shell")?;
                                    },
                                    Some(op) => {
                                        error!(?op, "Unknown channel operation in channel loop")
                                    }
                                    None => break,
                                }
                            }
                            channel_event = channel.wait() => {
                                match channel_event {
                                    Some(thrussh::ChannelMsg::Data { data }) => {
                                        let bytes: &[u8] = &data;
                                        tx.send(RCEvent::Output(
                                            channel_id,
                                            Bytes::from(BytesMut::from(bytes)),
                                        ))?;
                                    }
                                    Some(thrussh::ChannelMsg::Close) => {
                                        tx.send(RCEvent::Close(channel_id))?;
                                    },
                                    Some(thrussh::ChannelMsg::Success) => {
                                        tx.send(RCEvent::Success(channel_id))?;
                                    },
                                    Some(thrussh::ChannelMsg::Eof) => {
                                        tx.send(RCEvent::Eof(channel_id))?;
                                    }
                                    Some(thrussh::ChannelMsg::ExitStatus { exit_status }) => {
                                        tx.send(RCEvent::ExitStatus(channel_id, exit_status))?;
                                    }
                                    None => {
                                        tx.send(RCEvent::Close(channel_id))?;
                                        break
                                    },
                                    mgs => {
                                        debug!("unexpected message: {:?}", mgs);
                                    }
                                }
                            }
                        }
                    }
                    Ok::<(), anyhow::Error>(())
                }
            }));
        }
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        if let Some(session) = &mut self.session {
            let _ = session
                .lock()
                .await
                .disconnect(thrussh::Disconnect::ByApplication, "", "")
                .await;
            self.set_disconnected();
        }
        Ok(())
    }

    async fn _on_disconnect(&mut self) -> Result<()> {
        self.set_disconnected();
        Ok(())
    }

    // pub async fn _data(&mut self, channel: ChannelId, data: BytesMut, session: &mut Session) {
    //     debug!("Data {:?}", data);
    //     self.maybe_connect_remote().await;
    //     self.tx.send(RCCommand::Data(channel, data.freeze()));
    // }
}

impl Drop for RemoteClient {
    fn drop(&mut self) {
        for task in self.child_tasks.drain(..) {
            let _ = task.abort();
        }
        debug!("remote client dropped");
    }
}

struct ClientHandler {
    pub tx: UnboundedSender<ClientHandlerEvent>,
}

#[derive(Debug)]
enum ClientHandlerEvent {
    Disconnect,
}

impl thrussh::client::Handler for ClientHandler {
    type Error = anyhow::Error;
    type FutureUnit = futures::future::Ready<Result<(Self, Session), anyhow::Error>>;
    type FutureBool = futures::future::Ready<Result<(Self, bool), anyhow::Error>>;

    fn finished_bool(self, b: bool) -> Self::FutureBool {
        futures::future::ready(Ok((self, b)))
    }

    fn finished(self, session: Session) -> Self::FutureUnit {
        futures::future::ready(Ok((self, session)))
    }

    fn check_server_key(self, server_public_key: &PublicKey) -> Self::FutureBool {
        debug!("check_server_key: {:?}", server_public_key);
        self.finished_bool(true)
    }
}

impl Drop for ClientHandler {
    fn drop(&mut self) {
        let _ = self.tx.send(ClientHandlerEvent::Disconnect);
        debug!("handler dropped");
    }
}
