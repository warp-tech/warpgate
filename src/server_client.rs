use std::{collections::HashMap, sync::Arc};

use bytes::BytesMut;
use thrussh::{server::Session, ChannelId, CryptoVec};
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedSender},
    Mutex,
};

use crate::{
    misc::Client,
    remote_client::{RCCommand, RCEvent, RCState, RemoteClient},
};

pub struct ServerClient {
    clients: Arc<Mutex<HashMap<u64, Client>>>,
    id: u64,
    session_handle: Option<thrussh::server::Handle>,
    shell_channel: Option<ChannelId>,
    rc_tx: UnboundedSender<RCCommand>,
    rc_state: RCState,
}

impl ServerClient {
    pub fn new(clients: Arc<Mutex<HashMap<u64, Client>>>, id: u64) -> Arc<Mutex<Self>> {
        let (rce_tx, mut rce_rx) = unbounded_channel();
        let (rcc_tx, rcc_rx) = unbounded_channel();

        let this = Arc::new(Mutex::new(Self {
            clients,
            id,
            session_handle: None,
            shell_channel: None,
            rc_tx: rcc_tx,
            rc_state: RCState::NotInitialized,
        }));

        let rc = RemoteClient::new(this.clone(), rcc_rx, rce_tx);
        rc.start();

        tokio::spawn({
            let this = Arc::downgrade(&this);
            async move {
                loop {
                    let state = rce_rx.recv().await;
                    match state {
                        Some(e) => {
                            println!("[handler] event {:?}", e);
                            let this = this.upgrade();
                            if this.is_none() {
                                break;
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

    pub async fn ensure_client_registered(&mut self, session: &Session) {
        self.session_handle = Some(session.handle());
        // let mut clients = self.clients.lock().await;
        // if !clients.contains_key(&self.id) {
        //     let mut client = Client::new(session.handle());
        //     client.id = self.id;
        //     clients.insert(self.id, client);
        // }
    }

    pub async fn emit_service_message(&mut self, msg: &String) {
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

    pub async fn maybe_connect_remote(&mut self) {
        if self.rc_state == RCState::NotInitialized {
            self.rc_state = RCState::Connecting;
            self.emit_service_message(&"Connecting...".to_string())
                .await;
            self.rc_tx.send(RCCommand::Connect).unwrap();
        }
    }

    pub async fn handle_remote_event(&mut self, event: RCEvent) {
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

    pub async fn _channel_open_session(&mut self, channel: ChannelId, session: &mut Session) {
        println!("Channel open session {:?}", channel);
        self.shell_channel = Some(channel);
        self.ensure_client_registered(session).await;
        self.maybe_connect_remote().await;
        // {
        //     let mut clients = self.clients.lock().unwrap();
        //     clients.get_mut(&self.id).unwrap().shell_channel = Some(channel);
        // }
    }

    pub async fn _data(&mut self, channel: ChannelId, data: BytesMut, session: &mut Session) {
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
