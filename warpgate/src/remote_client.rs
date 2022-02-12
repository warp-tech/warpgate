use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use futures::future::OptionFuture;
use log::*;
use std::collections::HashMap;
use std::{sync::Arc, time::Duration};
use thrussh::client::{Channel, Handle, Session};
use thrussh::{ChannelId, Pty};
use thrussh_keys::key::PublicKey;
use thrussh_keys::load_secret_key;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::Mutex;

use crate::ServerClient;

#[derive(Clone, Debug)]
pub enum RCEvent {
    State(RCState),
    Output(ChannelId, Bytes),
    Success(ChannelId),
    Eof(ChannelId),
    Close(ChannelId),
    ExitStatus(ChannelId, u32),
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

#[derive(Debug)]
pub enum ChannelOperation {
    OpenShell(ChannelId),
    RequestPty(ChannelId, PtyRequest),
    RequestShell(ChannelId),
    Data(ChannelId, Bytes),
}

#[derive(Debug)]
pub enum RCCommand {
    Connect,
    Channel(ChannelOperation),
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
    channel_pipes: Arc<Mutex<HashMap<ChannelId, UnboundedSender<Bytes>>>>,
    channels_in_setup: HashMap<ChannelId, Channel>,
    pending_ops: Vec<ChannelOperation>,
    state: RCState,
    client_handler_rx: Option<UnboundedReceiver<ClientHandlerEvent>>,
}

impl RemoteClient {
    pub fn new(rx: UnboundedReceiver<RCCommand>, tx: UnboundedSender<RCEvent>) -> Self {
        Self {
            rx,
            tx,
            session: None,
            channel_pipes: Arc::new(Mutex::new(HashMap::new())),
            channels_in_setup: HashMap::new(),
            pending_ops: vec![],
            state: RCState::NotInitialized,
            client_handler_rx: None,
        }
    }

    fn set_disconnected(&mut self) {
        self.session = None;
        self.set_state(RCState::Disconnected);
        let _ = self.tx.send(RCEvent::Done);
    }

    fn set_state(&mut self, state: RCState) -> Result<()> {
        self.state = state.clone();
        self.tx.send(RCEvent::State(state))?;
        Ok(())
    }

    async fn apply_channel_op(&mut self, op: ChannelOperation) -> Result<()> {
        if self.state != RCState::Connected {
            self.pending_ops.push(op);
            return Ok(());
        }

        match op {
            ChannelOperation::OpenShell(channel_id) => match self.open_shell(channel_id).await {
                Ok(_) => {}
                Err(e) => {
                    self.set_disconnected();
                    debug!("open shell error: {}", e);
                    e.chain().skip(1).for_each(|e| debug!(": {}", e));
                }
            },
            ChannelOperation::RequestPty(channel_id, pty) => {
                match self.request_pty(channel_id, pty).await {
                    Ok(_) => {}
                    Err(e) => {
                        self.set_disconnected();
                        debug!("pty req error: {}", e);
                        e.chain().skip(1).for_each(|e| debug!(": {}", e));
                    }
                }
            }
            ChannelOperation::RequestShell(channel_id) => {
                match self.request_shell(channel_id).await {
                    Ok(_) => {}
                    Err(e) => {
                        self.set_disconnected();

                        debug!("shell req error: {}", e);
                        e.chain().skip(1).for_each(|e| debug!(": {}", e));
                    }
                }
            }
            ChannelOperation::Data(channel_id, data) => {
                let mut channel_pipes = self.channel_pipes.lock().await;
                match channel_pipes.get(&channel_id) {
                    Some(tx) => match tx.send(data) {
                        Ok(_) => {}
                        Err(SendError(_)) => {
                            channel_pipes.remove(&channel_id);
                        }
                    },
                    None => {
                        debug!("data for unknown channel {:?}", channel_id);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn start(mut self) {
        tokio::spawn(async move {
            match (async {
                loop {
                    tokio::select! {
                        cmd = self.rx.recv() => {
                            match cmd {
                                Some(RCCommand::Connect) => match self.connect().await {
                                    Ok(_) => {
                                        self.set_state(RCState::Connected)?;
                                        let mut ops = vec![];
                                        std::mem::swap(&mut self.pending_ops, &mut ops);
                                        for op in ops {
                                            self.apply_channel_op(op).await?;
                                        }
                                    }
                                    Err(e) => {
                                        self.set_disconnected();
                                        debug!("connect error: {}", e);
                                        e.chain().skip(1).for_each(|e| debug!(": {}", e));
                                    }
                                },
                                Some(RCCommand::Channel(op)) => {
                                    self.apply_channel_op(op).await?;
                                }
                                Some(RCCommand::Disconnect) => {
                                    self.disconnect().await?;
                                    self.set_disconnected();
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
                    };
                }
                Ok::<(), anyhow::Error>(())
            })
            .await
            {
                Ok(_) => {}
                Err(e) => {
                    debug!("error in command loop: {}", e);
                }
            }
            debug!("no more commmands");
        });
    }

    async fn connect(&mut self) -> Result<()> {
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
        let mut session = thrussh::client::connect(config, "192.168.78.233:22", handler)
            .await
            .with_context(|| "connect()")?;

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

    async fn request_pty(&mut self, channel_id: ChannelId, request: PtyRequest) -> Result<()> {
        let client_channel = self
            .channels_in_setup
            .get_mut(&channel_id)
            .ok_or(anyhow::anyhow!("channel not found"))?;
        client_channel
            .request_pty(
                true,
                &request.term,
                request.col_width,
                request.row_height,
                request.pix_width,
                request.pix_height,
                &request.modes,
            )
            .await?;
        Ok(())
    }

    async fn request_shell(&mut self, channel_id: ChannelId) -> Result<()> {
        let mut client_channel = self
            .channels_in_setup
            .remove(&channel_id)
            .ok_or(anyhow::anyhow!("channel not found"))?;
        client_channel.request_shell(true).await?;
        self.start_channel_pipe(client_channel).await;
        Ok(())
    }

    async fn start_channel_pipe(&mut self, mut channel: Channel) {
        let (tx, mut rx) = unbounded_channel();
        self.channel_pipes.lock().await.insert(channel.id(), tx);

        tokio::spawn({
            let tx = self.tx.clone();
            async move {
                loop {
                    tokio::select! {
                        incoming_data = rx.recv() => {
                            match incoming_data {
                                Some(data) => {
                                    match channel.data(&*data).await {
                                        Ok(_) => {}
                                        Err(e) => {
                                            debug!("data error on ch {:?}: {}", channel.id(), e);
                                            break
                                        }
                                    }
                                }
                                None => break,
                            }
                        }
                        channel_event = channel.wait() => {
                            match channel_event {
                                Some(thrussh::ChannelMsg::Data { data }) => {
                                    let bytes: &[u8] = &data;
                                    tx.send(RCEvent::Output(
                                        channel.id(),
                                        Bytes::from(BytesMut::from(bytes)),
                                    ))?;
                                }
                                Some(thrussh::ChannelMsg::Close) => {
                                    tx.send(RCEvent::Close(channel.id()))?;
                                },
                                Some(thrussh::ChannelMsg::Success) => {
                                    tx.send(RCEvent::Success(channel.id()))?;
                                },
                                Some(thrussh::ChannelMsg::Eof) => {
                                    tx.send(RCEvent::Eof(channel.id()))?;
                                }
                                Some(thrussh::ChannelMsg::ExitStatus { exit_status }) => {
                                    tx.send(RCEvent::ExitStatus(channel.id(), exit_status))?;
                                }
                                None => {
                                    tx.send(RCEvent::Close(channel.id()))?;
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
        });
    }

    async fn open_shell(&mut self, channel_id: ChannelId) -> Result<()> {
        if let Some(session) = &self.session {
            let mut session = session.lock().await;
            let channel = session.channel_open_session().await?;
            self.channels_in_setup.insert(channel_id, channel);
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
