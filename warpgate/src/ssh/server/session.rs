use ansi_term::Colour;
use anyhow::Result;
use bytes::{Bytes, BytesMut};
use std::net::ToSocketAddrs;
use std::sync::Arc;
use thrussh::Sig;
use thrussh::{server::Session, CryptoVec};
use tokio::sync::oneshot;
use tokio::sync::{mpsc::UnboundedSender, Mutex};
use tracing::*;

use super::super::{
    ChannelOperation, PtyRequest, RCCommand, RCEvent, RCState, RemoteClient, ServerChannelId,
};
use crate::compat::ContextExt;
use warpgate_common::{SessionState, State};

pub struct ServerSession {
    id: u64,
    session_handle: Option<thrussh::server::Handle>,
    pty_channels: Vec<ServerChannelId>,
    all_channels: Vec<ServerChannelId>,
    rc_tx: UnboundedSender<RCCommand>,
    rc_abort_tx: Option<oneshot::Sender<()>>,
    rc_state: RCState,
    remote_addr: std::net::SocketAddr,
    state: Arc<Mutex<State>>,
    session_state: Arc<Mutex<SessionState>>,
}

impl std::fmt::Debug for ServerSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[S{} - {}]", self.id, self.remote_addr)
    }
}

impl ServerSession {
    pub fn new(
        id: u64,
        remote_addr: std::net::SocketAddr,
        state: Arc<Mutex<State>>,
        session_state: Arc<Mutex<SessionState>>,
    ) -> Arc<Mutex<Self>> {
        let mut rc_handles = RemoteClient::create(id);

        let this = Self {
            id,
            session_handle: None,
            pty_channels: vec![],
            all_channels: vec![],
            rc_tx: rc_handles.command_tx,
            rc_abort_tx: rc_handles.abort_tx,
            rc_state: RCState::NotInitialized,
            remote_addr,
            state,
            session_state,
        };

        info!(session=?this, "New connection");

        let session_debug_tag = format!("{:?}", this);
        let this = Arc::new(Mutex::new(this));

        let name = format!("SSH S{} client events", id);
        tokio::task::Builder::new().name(&name).spawn({
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
                let _ = handle.data(channel.0, CryptoVec::from_slice(data)).await;
            }
        }
    }

    pub async fn maybe_connect_remote(&mut self) -> Result<()> {
        if self.rc_state == RCState::NotInitialized {
            self.rc_state = RCState::Connecting;
            let address = "192.168.78.233:22"
                .to_socket_addrs()
                .unwrap()
                .next()
                .unwrap();
            self.rc_tx.send(RCCommand::Connect(address))?;
            self.emit_service_message(&format!("Connecting to {address}"))
                .await;
        }
        Ok(())
    }

    pub async fn handle_remote_event(&mut self, event: RCEvent) -> Result<()> {
        match event {
            RCEvent::State(state) => {
                self.rc_state = state;
                match &self.rc_state {
                    RCState::Connected => {
                        self.emit_service_message(&"Connected").await;
                    }
                    RCState::Disconnected => {
                        drop(self.session_handle.take());
                    }
                    _ => {}
                }
            }
            RCEvent::ConnectionError => {
                self.emit_service_message(&"Connection failed").await;
            }
            RCEvent::AuthError => {
                self.emit_service_message(&"Authentication failed").await;
            }
            RCEvent::Output(channel, data) => {
                self.maybe_with_session(|handle| async move {
                    handle
                        .data(channel.0, CryptoVec::from_slice(&data))
                        .await
                        .map_err(|_| ())
                        .context("failed to send data")
                })
                .await?;
            }
            RCEvent::Success(channel) => {
                self.maybe_with_session(|handle| async move {
                    handle
                        .channel_success(channel.0)
                        .await
                        .context("failed to send data")
                })
                .await?;
            }
            RCEvent::Close(channel) => {
                self.maybe_with_session(|handle| async move {
                    handle.close(channel.0).await.context("failed to close ch")
                })
                .await?;
            }
            RCEvent::Eof(channel) => {
                self.maybe_with_session(|handle| async move {
                    handle.eof(channel.0).await.context("failed to send eof")
                })
                .await?;
            }
            RCEvent::ExitStatus(channel, code) => {
                self.maybe_with_session(|handle| async move {
                    handle
                        .exit_status_request(channel.0, code)
                        .await
                        .context("failed to send exit status")
                })
                .await?;
            }
            RCEvent::ExitSignal {
                channel_id,
                signal_name,
                core_dumped,
                error_message,
                lang_tag,
            } => {
                self.maybe_with_session(|handle| async move {
                    handle
                        .exit_signal_request(
                            channel_id.0,
                            signal_name,
                            core_dumped,
                            error_message,
                            lang_tag,
                        )
                        .await
                        .context("failed to send exit status")?;
                    Ok(())
                })
                .await?;
            }
            RCEvent::Done => {}
            RCEvent::ExtendedData {
                channel_id,
                data,
                ext,
            } => {
                self.maybe_with_session(|handle| async move {
                    handle
                        .extended_data(channel_id.0, ext, CryptoVec::from_slice(&data))
                        .await
                        .map_err(|_| ())
                        .context("failed to send extended data")?;
                    Ok(())
                })
                .await?;
            }
        }
        Ok(())
    }

    async fn maybe_with_session<'a, FN, FT, R>(&'a mut self, f: FN) -> Result<R>
    where
        FN: FnOnce(&'a mut thrussh::server::Handle) -> FT + 'a,
        FT: futures::Future<Output = Result<R>>,
        R: Default,
    {
        if let Some(handle) = &mut self.session_handle {
            f(handle).await?;
        }
        Ok(Default::default())
    }

    pub async fn _channel_open_session(
        &mut self,
        channel: ServerChannelId,
        session: &mut Session,
    ) -> Result<()> {
        debug!(session=?self, ?channel, "Opening channel");
        self.all_channels.push(channel);
        self.session_handle = Some(session.handle());
        self.rc_tx
            .send(RCCommand::Channel(channel, ChannelOperation::OpenShell))?;
        Ok(())
    }

    pub async fn _channel_pty_request(
        &mut self,
        channel: ServerChannelId,
        request: PtyRequest,
    ) -> Result<()> {
        self.rc_tx.send(RCCommand::Channel(
            channel,
            ChannelOperation::RequestPty(request),
        ))?;
        let _ = self
            .session_handle
            .as_mut()
            .unwrap()
            .channel_success(channel.0)
            .await;
        self.pty_channels.push(channel);
        let _ = self.maybe_connect_remote().await;
        Ok(())
    }

    pub async fn _window_change_request(&mut self, channel: ServerChannelId, request: PtyRequest) {
        self.send_command(RCCommand::Channel(
            channel,
            ChannelOperation::ResizePty(request),
        ));
    }

    pub async fn _channel_exec_request(&mut self, channel: ServerChannelId, data: Bytes) -> Result<()> {
        match std::str::from_utf8(&data) {
            Err(e) => {
                error!(session=?self, channel=?channel.0, ?data, "Requested exec - invalid UTF-8");
                anyhow::bail!(e)
            }
            Ok::<&str, _>(command) => {
                debug!(session=?self, channel=?channel.0, %command, "Requested exec");
                let _ = self.maybe_connect_remote().await;
                self.send_command(RCCommand::Channel(
                    channel,
                    ChannelOperation::RequestExec(command.to_string()),
                ));
            }
        }
        Ok(())
    }

    pub async fn _channel_shell_request(&mut self, channel: ServerChannelId) -> Result<()> {
        self.rc_tx
            .send(RCCommand::Channel(channel, ChannelOperation::RequestShell))?;
        info!(session=?self, ?channel, "Opening shell");
        let _ = self
            .session_handle
            .as_mut()
            .unwrap()
            .channel_success(channel.0)
            .await;
        Ok(())
    }

    pub async fn _channel_subsystem_request(&mut self, channel: ServerChannelId, name: String) {
        info!(session=?self, ?channel, "Requesting subsystem {}", &name);
        self.send_command(RCCommand::Channel(
            channel,
            ChannelOperation::RequestSubsystem(name),
        ));
    }

    pub async fn _data(&mut self, channel: ServerChannelId, data: BytesMut) {
        debug!(session=?self, channel=?channel.0, ?data, "Data");
        let _ = self.maybe_connect_remote().await;
        if self.rc_state == RCState::Connecting && data.get(0) == Some(&3) {
            info!(session=?self, ?channel, "User requested connection abort (Ctrl-C)");
            self.request_disconnect().await;
            return;
        }
        self.send_command(RCCommand::Channel(
            channel,
            ChannelOperation::Data(data.freeze()),
        ));
    }

    pub async fn _extended_data(&mut self, channel: ServerChannelId, code: u32, data: BytesMut) {
        debug!(session=?self, channel=?channel.0, ?data, "Data");
        self.send_command(RCCommand::Channel(
            channel,
            ChannelOperation::ExtendedData {
                ext: code,
                data: data.freeze(),
            },
        ));
    }

    pub async fn _auth_publickey(
        &mut self,
        user: String,
        key: &thrussh_keys::key::PublicKey,
    ) -> thrussh::server::Auth {
        info!(session=?self, "Public key auth as {} with key {}", user, key.fingerprint());
        self._auth_accept(&user).await
    }

    async fn _auth_accept(&mut self, username: &str) -> thrussh::server::Auth {
        info!(session=?self, "Authenticated");
        self.session_state.lock().await.username = Some(username.into());
        thrussh::server::Auth::Accept
    }

    pub async fn _channel_close(&mut self, channel: ServerChannelId) {
        debug!(session=?self, ?channel, "Closing channel");
        self.send_command(RCCommand::Channel(channel, ChannelOperation::Close));
    }

    pub async fn _channel_eof(&mut self, channel: ServerChannelId) {
        debug!(session=?self, ?channel, "EOF");
        self.send_command(RCCommand::Channel(channel, ChannelOperation::Eof));
    }

    pub async fn _channel_signal(&mut self, channel: ServerChannelId, signal: Sig) {
        debug!(session=?self, ?channel, ?signal, "Signal");
        self.send_command(RCCommand::Channel(
            channel,
            ChannelOperation::Signal(signal),
        ));
    }

    fn send_command(&mut self, command: RCCommand) {
        let _ = self.rc_tx.send(command);
    }

    pub async fn _disconnect(&mut self) {
        debug!(session=?self, "Client disconnect requested");
        self.request_disconnect().await;
    }

    async fn request_disconnect(&mut self) {
        debug!(session=?self, "Disconnecting");
        if let Some(s) = self.rc_abort_tx.take() {
            let _ = s.send(());
        }
        if self.rc_state != RCState::NotInitialized && self.rc_state != RCState::Disconnected {
            self.send_command(RCCommand::Disconnect);
        }
    }

    // async fn disconnect(&mut self) {
    //     let channels: Vec<ServerChannelId> = self.all_channels.drain(..).collect();
    //     let _ = self.maybe_with_session(|handle| async move {
    //         for ch in channels {
    //             let _ = handle.close(ch.0);
    //         }
    //         Ok(())
    //     }).await;
    // }
}

impl Drop for ServerSession {
    fn drop(&mut self) {
        let id = self.id;
        let state = self.state.clone();
        tokio::spawn(async move {
            state.lock().await.remove_session(id);
        });
        info!(session=?self, "Closed connection");
        debug!("Dropped");
    }
}
