use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use std::{sync::Arc, time::Duration};
use thrussh::client::{Handle, Session};
use thrussh::{ChannelId, Pty};
use thrussh_keys::key::PublicKey;
use thrussh_keys::load_secret_key;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::Mutex;

use crate::ServerClient;

#[derive(Clone, Debug)]
pub enum RCEvent {
    Connected,
    Disconnected,
    Output(ChannelId, Bytes),
}

#[derive(Debug)]
pub enum RCCommand {
    Connect,
    OpenShell(UnboundedReceiver<Bytes>, ChannelId),
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
                    Some(RCCommand::OpenShell(rx, channel_id)) => {
                        match self.open_shell(rx, channel_id).await {
                            Ok(_) => {}
                            Err(e) => {
                                self.tx.send(RCEvent::Disconnected).unwrap();
                                println!("[rc] open shell error: {}", e);
                                e.chain().skip(1).for_each(|e| println!(": {}", e));
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
        mut rx: UnboundedReceiver<Bytes>,
        channel_id: ChannelId,
    ) -> Result<()> {
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
            let channel = Arc::new(Mutex::new(channel));
            tokio::spawn({
                let channel = channel.clone();
                async move {
                    loop {
                        match rx.recv().await {
                            Some(data) => {
                                channel.lock().await.data(&*data).await?;
                            }
                            None => break,
                        }
                    }
                    Ok::<(), anyhow::Error>(())
                }
            });
            tokio::spawn({
                let tx = self.tx.clone();
                async move {
                    loop {
                        match channel.lock().await.wait().await {
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
