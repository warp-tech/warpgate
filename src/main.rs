#![feature(type_alias_impl_trait)]
use bytes::BytesMut;
use core::future::Future;
use futures::future::{ready, Ready};
use futures::FutureExt;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use thrussh::server::{Auth, Session};
use thrussh::*;
use thrussh_keys::*;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    let server_key = load_secret_key("host_key", None).unwrap();
    let mut config = thrussh::server::Config::default();
    config.auth_rejection_time = std::time::Duration::from_secs(1);
    config.keys.push(server_key);
    config.methods = MethodSet::PUBLICKEY;
    let config = Arc::new(config);
    let sh = Server {
        clients: Arc::new(Mutex::new(HashMap::new())),
        last_client_id: 0,
    };
    thrussh::server::run(config, "0.0.0.0:2222", sh)
        .await
        .unwrap();
}

struct Client {
    id: u64,
    shell_channel: Option<ChannelId>,
    handle: thrussh::server::Handle,
}

impl Client {
    fn new(handle: thrussh::server::Handle) -> Self {
        Self {
            id: 0,
            shell_channel: None,
            handle,
        }
    }
}

#[derive(Clone)]
struct Server {
    clients: Arc<Mutex<HashMap<u64, Client>>>,
    last_client_id: u64,
}

impl server::Server for Server {
    type Handler = ServerHandler;
    fn new(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
        self.last_client_id += 1;
        let client = ServerClient::new(self.clients.clone(), self.last_client_id);
        ServerHandler {
            client: client.clone(),
        }
    }
}

#[derive(Clone, Debug)]
enum RCEvent {
    Connected,
    Disconnected,
}

#[derive(Clone, Debug)]
enum RCCommand {
    Connect,
}

#[derive(Clone, Debug, PartialEq)]
enum RCState {
    NotInitialized,
    Connecting,
    Connected,
    Disconnected,
}

struct RemoteClient {
    client: Arc<Mutex<ServerClient>>,
    rx: tokio::sync::mpsc::UnboundedReceiver<RCCommand>,
    tx: tokio::sync::mpsc::UnboundedSender<RCEvent>,
}

impl RemoteClient {
    pub fn start(mut self) {
        tokio::spawn(async move {
            loop {
                let cmd = self.rx.recv().await;
                match cmd {
                    Some(RCCommand::Connect) => {
                        println!("[rc] connecting");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        println!("[rc] connected");
                        self.tx.send(RCEvent::Connected).unwrap();
                    }
                    None => {
                        break;
                    }
                }
            }
            println!("[rc] no more commmands");
        });
    }
}

struct ServerClient {
    clients: Arc<Mutex<HashMap<u64, Client>>>,
    id: u64,
    session_handle: Option<thrussh::server::Handle>,
    shell_channel: Option<ChannelId>,
    rc_tx: tokio::sync::mpsc::UnboundedSender<RCCommand>,
    rc_state: RCState,
}

impl ServerClient {
    fn new(clients: Arc<Mutex<HashMap<u64, Client>>>, id: u64) -> Arc<Mutex<Self>> {
        let (rce_tx, mut rce_rx) = tokio::sync::mpsc::unbounded_channel();
        let (rcc_tx, rcc_rx) = tokio::sync::mpsc::unbounded_channel();

        let this = Arc::new(Mutex::new(Self {
            clients,
            id,
            session_handle: None,
            shell_channel: None,
            rc_tx: rcc_tx,
            rc_state: RCState::NotInitialized,
        }));

        let rc = RemoteClient {
            client: this.clone(),
            rx: rcc_rx,
            tx: rce_tx,
        };
        rc.start();

        tokio::spawn({
            let this = Arc::downgrade(&this.clone());
            async move {
                loop {
                    let state = rce_rx.recv().await;
                    match state {
                        Some(e) => {
                            println!("[handler] event {:?}", e);
                            let this = this.upgrade();
                            if this.is_none() {
                                break
                            }
                            let t = this.unwrap();
                            let this = &mut t.lock().await;
                            this.handle_remote_event(e).await;
                        }
                        None => {
                            break;
                        }
                    }
                }
                println!("[handler] no more events from rc");
            }
        });

        this
    }

    async fn ensure_client_registered(&mut self, session: &Session) {
        self.session_handle = Some(session.handle());
        // let mut clients = self.clients.lock().await;
        // if !clients.contains_key(&self.id) {
        //     let mut client = Client::new(session.handle());
        //     client.id = self.id;
        //     clients.insert(self.id, client);
        // }
    }

    async fn emit_service_message(&mut self, msg: &String) {
        if let Some(handle) = &mut self.session_handle {
            if let Some(shell_channel) = &self.shell_channel {
                let _ = handle
                    .data(
                        *shell_channel,
                        CryptoVec::from_slice(format!("{}\r\n", msg).as_bytes()),
                    )
                    .await;
            }
        }
    }

    async fn maybe_connect_remote(&mut self) {
        if self.rc_state == RCState::NotInitialized {
            self.rc_state = RCState::Connecting;
            self.emit_service_message(&"Connecting...".to_string())
                .await;
            self.rc_tx.send(RCCommand::Connect).unwrap();
        }
    }

    async fn handle_remote_event(&mut self, event: RCEvent) {
        match event {
            RCEvent::Connected => {
                self.rc_state = RCState::Connected;
                self.emit_service_message(&"Connected".to_string()).await;
            }
            RCEvent::Disconnected => {
                self.rc_state = RCState::Disconnected;
                self.emit_service_message(&"Disconnected".to_string()).await;
            }
        }
    }

    async fn _channel_open_session(&mut self, channel: ChannelId, session: &mut Session) {
        println!("Channel open session {:?}", channel);
        self.shell_channel = Some(channel);
        self.ensure_client_registered(&session).await;
        self.maybe_connect_remote().await;
        // {
        //     let mut clients = self.clients.lock().unwrap();
        //     clients.get_mut(&self.id).unwrap().shell_channel = Some(channel);
        // }
    }

    async fn _data(&mut self, channel: ChannelId, data: BytesMut, session: &mut Session) {
        println!("Data {:?}", data);
        self.maybe_connect_remote().await;
        session.data(channel, CryptoVec::from_slice(&data));
    }

    fn close(&mut self) {}
}

impl Drop for ServerClient {
    fn drop(&mut self) {
        self.close();
        println!("[client] dropped");
    }
}

struct ServerHandler {
    client: Arc<Mutex<ServerClient>>,
}

impl ServerHandler {
    async fn _data(
        self,
        channel: ChannelId,
        data: BytesMut,
        mut session: Session,
    ) -> anyhow::Result<(Self, Session)> {
        self.client
            .lock()
            .await
            ._data(channel, data, &mut session)
            .await;
        Ok((self, session))
    }

    async fn _finished(self, s: Session) -> anyhow::Result<(ServerHandler, Session)> {
        Ok((self, s))
    }

    async fn _channel_open_session(
        self,
        channel: ChannelId,
        mut session: Session,
    ) -> anyhow::Result<(ServerHandler, Session)> {
        self.client
            .lock()
            .await
            ._channel_open_session(channel, &mut session)
            .await;
        Ok((self, session))
    }
}

impl server::Handler for ServerHandler {
    type Error = anyhow::Error;
    type FutureAuth = Ready<anyhow::Result<(Self, server::Auth)>>;
    type FutureUnit = Pin<Box<dyn Future<Output = anyhow::Result<(Self, Session)>> + Send>>;
    type FutureBool = Ready<anyhow::Result<(Self, Session, bool)>>;

    fn finished_auth(self, auth: Auth) -> Self::FutureAuth {
        println!("Finished auth {:?}", auth);
        ready(Ok((self, auth)))
    }

    fn finished_bool(self, b: bool, s: Session) -> Self::FutureBool {
        ready(Ok((self, s, b)))
    }

    fn finished(self, s: Session) -> Self::FutureUnit {
        self._finished(s).boxed()
    }

    fn channel_open_session(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
        self._channel_open_session(channel, session).boxed()
    }

    fn auth_publickey(self, user: &str, key: &key::PublicKey) -> Self::FutureAuth {
        println!("Auth {:?} with key {:?}", user, key);
        self.finished_auth(Auth::Accept)
    }

    fn auth_password(self, user: &str, password: &str) -> Self::FutureAuth {
        println!("Auth {:?} with pw {:?}", user, password);
        self.finished_auth(Auth::Accept)
    }

    fn data(self, channel: ChannelId, data: &[u8], session: Session) -> Self::FutureUnit {
        let data = BytesMut::from(data);
        self._data(channel, data, session).boxed()
    }
}

impl Drop for ServerHandler {
    fn drop(&mut self) {
        println!("Server handler dropped");
    }
}
