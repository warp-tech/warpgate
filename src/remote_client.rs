use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use tokio::sync::mpsc::error::SendError;
use std::collections::HashMap;
use std::{sync::Arc, time::Duration};
use thrussh::client::{Handle, Session};
use thrussh::{ChannelId, Pty};
use thrussh_keys::key::PublicKey;
use thrussh_keys::load_secret_key;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::sync::Mutex;

use crate::ServerClient;

#[derive(Clone, Debug)]
pub enum RCEvent {
    Connected,
    Disconnected,
    Output(ChannelId, Bytes),
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
pub enum RCCommand {
    Connect,
    OpenShell(ChannelId),
    Data(ChannelId, Bytes),
    RequestPty(ChannelId, PtyRequest),
}

#[derive(Clone, Debug, PartialEq)]
pub enum RCState {
    NotInitialized,
    Connecting,
    Connected,
    Disconnected,
}

pub struct RemoteClient {
    client: Arc<Mutex<ServerClient>>,
    rx: UnboundedReceiver<RCCommand>,
    tx: UnboundedSender<RCEvent>,
    session: Option<Arc<Mutex<Handle<ClientHandler>>>>,
    channel_map: Arc<Mutex<HashMap<ChannelId, UnboundedSender<Bytes>>>>,
}

impl RemoteClient {
    pub fn new(
        client: Arc<Mutex<ServerClient>>,
        rx: UnboundedReceiver<RCCommand>,
        tx: UnboundedSender<RCEvent>,
    ) -> Self {
        Self {
            client,
            rx,
            tx,
            session: None,
            channel_map: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn start(mut self) {
        tokio::spawn(async move {
            loop {
                let cmd = self.rx.recv().await;
                match cmd {
                    Some(RCCommand::Connect) => match self.connect().await {
                        Ok(_) => {
                            self.tx.send(RCEvent::Connected).unwrap();
                        }
                        Err(e) => {
                            self.tx.send(RCEvent::Disconnected).unwrap();
                            println!("[rc] connect error: {}", e);
                            e.chain().skip(1).for_each(|e| println!(": {}", e));
                        }
                    },
                    Some(RCCommand::OpenShell(channel_id)) => {
                        match self.open_shell(channel_id).await {
                            Ok(_) => {}
                            Err(e) => {
                                self.tx.send(RCEvent::Disconnected).unwrap();
                                println!("[rc] open shell error: {}", e);
                                e.chain().skip(1).for_each(|e| println!(": {}", e));
                            }
                        }
                    }
                    Some(RCCommand::RequestPty(_, _)) => {}
                    Some(RCCommand::Data(channel_id, data)) => {
                        let mut channel_map = self.channel_map.lock().await;
                        match channel_map.get(&channel_id) {
                            Some(tx) => {
                                match tx.send(data) {
                                    Ok(_) => {}
                                    Err(SendError(_)) => {
                                        channel_map.remove(&channel_id);
                                    }
                                }
                            }
                            None => {
                                println!("[rc] data for unknown channel {:?}", channel_id);
                            }
                        }
                    }
                    None => {
                        break;
                    }
                }
            }
            println!("[rc] no more commmands");
        });
    }

    async fn connect(&mut self) -> Result<()> {
        println!("[rc] connecting");
        let client_key = load_secret_key("/Users/eugene/.ssh/id_rsa", None)
            .with_context(|| "load_secret_key()")?;
        let client_key = Arc::new(client_key);
        let config = thrussh::client::Config {
            ..Default::default()
        };
        let config = Arc::new(config);

        let handler = ClientHandler {};

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
            println!("[rc] auth failed");
            let _ = session
                .disconnect(thrussh::Disconnect::ByApplication, "", "")
                .await;
            anyhow::bail!("auth failed");
        }

        self.session = Some(Arc::new(Mutex::new(session)));

        println!("[rc] done");
        Ok(())
    }

    async fn open_shell(
        &mut self,
        channel_id: ChannelId,
    ) -> Result<()> {
        let (tx, mut rx) = unbounded_channel();
        self.channel_map.lock().await.insert(channel_id, tx);

        if let Some(session) = &self.session {
            let mut session = session.lock().await;
            let mut channel = session.channel_open_session().await?;

            channel
                .request_pty(
                    true,
                    "xterm256-color",
                    80,
                    25,
                    0,
                    0,
                    &[(Pty::TTY_OP_END, 0)],
                )
                .await?;
            channel.request_shell(true).await?;

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
                                                println!("[rc] data error on ch {:?}: {}", channel_id, e);
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
                                            channel_id,
                                            Bytes::from(BytesMut::from(bytes)),
                                        ))?;
                                    }
                                    Some(thrussh::ChannelMsg::Close) | None => break,
                                    Some(thrussh::ChannelMsg::Success) => {},
                                    None => break,
                                    mgs => {
                                        println!("[rc] unexpected message: {:?}", mgs);
                                    }
                                }
                            }
                        }

                    }
                    Ok::<(), anyhow::Error>(())
                }
            });
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
            self.session = None;
            self.tx.send(RCEvent::Disconnected)?;
        }
        Ok(())
    }

    // pub async fn _data(&mut self, channel: ChannelId, data: BytesMut, session: &mut Session) {
    //     println!("Data {:?}", data);
    //     self.maybe_connect_remote().await;
    //     self.tx.send(RCCommand::Data(channel, data.freeze()));
    // }
}

struct ClientHandler {
    // data_queue_rx: UnboundedReceiver<(ChannelId, Bytes)>,
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
        println!("check_server_key: {:?}", server_public_key);
        self.finished_bool(true)
    }
}
