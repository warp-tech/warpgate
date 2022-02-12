use ansi_term::Colour;
use anyhow::Result;
use bytes::BytesMut;
use std::{collections::HashMap, sync::Arc};
use thrussh::{server::Session, ChannelId, CryptoVec};
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedSender},
    Mutex,
};
use tracing::*;

use crate::remote_client::{ChannelOperation, PtyRequest};
use crate::{
    misc::Client,
    remote_client::{RCCommand, RCEvent, RCState, RemoteClient},
};

pub struct ServerClient {
    clients: Arc<Mutex<HashMap<u64, Client>>>,
    id: u64,
    session_handle: Option<thrussh::server::Handle>,
    pty_channels: Vec<ChannelId>,
    rc_tx: UnboundedSender<RCCommand>,
    rc_state: RCState,
    remote_addr: Option<std::net::SocketAddr>,
}

impl std::fmt::Debug for ServerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[S{} - {}]",
            self.id,
            self.remote_addr
                .map(|x| x.to_string())
                .unwrap_or("unknown".into())
        )
    }
}

impl ServerClient {
    pub fn new(
        clients: Arc<Mutex<HashMap<u64, Client>>>,
        id: u64,
        remote_addr: Option<std::net::SocketAddr>,
    ) -> Arc<Mutex<Self>> {
        let mut rc_handles = RemoteClient::create();

        let this = Self {
            clients,
            id,
            session_handle: None,
            pty_channels: vec![],
            rc_tx: rc_handles.command_tx,
            rc_state: RCState::NotInitialized,
            remote_addr,
        };

        info!(session=?this, "New connection");

        let session_debug_tag = format!("{:?}", this);
        let this = Arc::new(Mutex::new(this));

        tokio::spawn({
            let this = Arc::downgrade(&this);
            async move {
                loop {
                    let state = rc_handles.event_rx.recv().await;
                    match state {
                        Some(e) => {
                            debug!(session=%session_debug_tag, event=?e, "Event");
                            let this = this.upgrade();
                            if this.is_none() {
                                break;
                            }
                            let t = this.unwrap();
                            let this = &mut t.lock().await;
                            match e {
                                RCEvent::Done => break,
                                e => match this.handle_remote_event(e).await {
                                    Err(err) => {
                                        error!(session=%session_debug_tag, "Event handler error: {:?}", err);
                                        break;
                                    }
                                    _ => (),
                                },
                            }
                        }
                        None => {
                            break;
                        }
                    }
                }
                debug!(session=%session_debug_tag, "No more events from RC");
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

    pub async fn emit_service_message(&mut self, msg: &str) {
        debug!(session=?self, "Service message: {}", msg);
        self.emit_pty_output(
            format!(
                "{} {}\r\n",
                Colour::Black.on(Colour::Blue).bold().paint(" warpgate "),
                msg,
            )
            .as_bytes(),
        )
        .await;
    }

    pub async fn emit_pty_output(&mut self, data: &[u8]) {
        if let Some(handle) = &mut self.session_handle {
            for channel in &mut self.pty_channels {
                let _ = handle.data(*channel, CryptoVec::from_slice(data)).await;
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

    pub async fn handle_remote_event(&mut self, event: RCEvent) -> Result<()> {
        match event {
            RCEvent::State(state) => {
                self.rc_state = state;
                match &self.rc_state {
                    RCState::Connected => {
                        self.emit_service_message(&"Connected".to_string()).await;
                    }
                    RCState::Disconnected => {
                        self.emit_service_message(&"Disconnected".to_string()).await;
                        drop(self.session_handle.take());
                    }
                    _ => {}
                }
            }
            RCEvent::Output(channel, data) => {
                if let Some(handle) = &mut self.session_handle {
                    match handle.data(channel, CryptoVec::from_slice(&data)).await {
                        Ok(_) => {}
                        Err(_) => anyhow::bail!("failed to send data"),
                    }
                }
            }
            RCEvent::Success(channel) => {
                if let Some(handle) = &mut self.session_handle {
                    match handle.channel_success(channel).await {
                        Ok(_) => {}
                        Err(_) => anyhow::bail!("failed to send data"),
                    }
                }
            }
            RCEvent::Close(channel) => {
                if let Some(handle) = &mut self.session_handle {
                    match handle.close(channel).await {
                        Ok(_) => {}
                        Err(_) => anyhow::bail!("failed to close ch"),
                    }
                }
            }
            RCEvent::Eof(channel) => {
                if let Some(handle) = &mut self.session_handle {
                    match handle.eof(channel).await {
                        Ok(_) => {}
                        Err(_) => anyhow::bail!("failed to send eof"),
                    }
                }
            }
            RCEvent::ExitStatus(channel, code) => {
                if let Some(handle) = &mut self.session_handle {
                    match handle.exit_status_request(channel, code).await {
                        Ok(_) => {}
                        Err(_) => anyhow::bail!("failed to send exit status"),
                    }
                }
            }
            e => {
                warn!(session=?self, event=?e, "Unhandled event");
            }
        }
        Ok(())
    }

    pub async fn _channel_open_session(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<()> {
        debug!(session=?self, ?channel, "Opening channel");
        self.ensure_client_registered(session).await;
        self.rc_tx
            .send(RCCommand::Channel(ChannelOperation::OpenShell(channel)))?;
        Ok(())
    }

    pub async fn _channel_pty_request(
        &mut self,
        channel: ChannelId,
        request: PtyRequest,
    ) -> Result<()> {
        self.rc_tx
            .send(RCCommand::Channel(ChannelOperation::RequestPty(
                channel, request,
            )))?;
        let _ = self
            .session_handle
            .as_mut()
            .unwrap()
            .channel_success(channel)
            .await;
        self.pty_channels.push(channel);
        self.maybe_connect_remote().await;
        Ok(())
    }

    pub async fn _channel_shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<()> {
        self.rc_tx
            .send(RCCommand::Channel(ChannelOperation::RequestShell(channel)))?;
        info!(session=?self, ?channel, "Opening shell");
        let _ = self
            .session_handle
            .as_mut()
            .unwrap()
            .channel_success(channel)
            .await;
        Ok(())
    }

    pub async fn _data(&mut self, channel: ChannelId, data: BytesMut, session: &mut Session) {
        debug!(session=?self,?data, "Data");
        self.maybe_connect_remote().await;
        if self.rc_state == RCState::Connecting && data.get(0) == Some(&3) {
            info!(session=?self, ?channel, "User requested connection abort (Ctrl-C)");
            self._disconnect().await;
            return;
        }
        let _ = self.rc_tx.send(RCCommand::Channel(ChannelOperation::Data(
            channel,
            data.freeze(),
        )));
    }

    pub async fn _auth_publickey(
        &mut self,
        user: String,
        key: &thrussh_keys::key::PublicKey,
    ) -> thrussh::server::Auth {
        info!(session=?self, "Public key auth as {} with key {}", user, key.fingerprint());
        self._auth_accept()
    }

    fn _auth_accept(&mut self) -> thrussh::server::Auth {
        info!(session=?self, "Authenticated");
        thrussh::server::Auth::Accept
    }

    pub async fn _channel_close(&mut self, channel: ChannelId, session: &mut Session) {
        debug!(session=?self, ?channel, "Closing channel");
    }

    pub async fn _disconnect(&mut self) {
        debug!(session=?self, "Disconnecting");
        if self.rc_state != RCState::NotInitialized && self.rc_state != RCState::Disconnected {
            self.rc_tx.send(RCCommand::Disconnect).unwrap();
        }
    }
}

impl Drop for ServerClient {
    fn drop(&mut self) {
        info!(session=?self, "Closed connection");
    }
}
