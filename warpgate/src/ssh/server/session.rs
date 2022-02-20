use ansi_term::Colour;
use anyhow::Result;
use bytes::{Bytes, BytesMut};
use std::net::ToSocketAddrs;
use std::sync::Arc;
use thrussh::Sig;
use thrussh::{server::Session, CryptoVec};
use thrussh_keys::key::PublicKey;
use thrussh_keys::PublicKeyBase64;
use tokio::sync::oneshot;
use tokio::sync::{mpsc::UnboundedSender, Mutex};
use tracing::*;

use super::super::{
    ChannelOperation, PtyRequest, RCCommand, RCEvent, RCState, RemoteClient, ServerChannelId,
};
use super::session_handle::{SSHSessionHandle, SessionHandleCommand};
use crate::compat::ContextExt;
use warpgate_common::{SessionState, State, Target, User, UserAuth};

#[derive(Clone)]
enum TargetSelection {
    None,
    NotFound(String),
    Found(Target),
}

struct Selector {
    username: String,
    target_name: String,
}

impl From<&str> for Selector {
    fn from(s: &str) -> Self {
        let mut parts = s.splitn(2, ':');
        let username = parts.next().unwrap_or("").to_string();
        let target_name = parts.next().unwrap_or("").to_string();
        Selector {
            username,
            target_name,
        }
    }
}

pub struct ServerSession {
    pub id: u64,
    session_handle: Option<thrussh::server::Handle>,
    pty_channels: Vec<ServerChannelId>,
    all_channels: Vec<ServerChannelId>,
    rc_tx: UnboundedSender<RCCommand>,
    rc_abort_tx: Option<oneshot::Sender<()>>,
    rc_state: RCState,
    remote_address: std::net::SocketAddr,
    state: Arc<Mutex<State>>,
    session_state: Arc<Mutex<SessionState>>,
    target: TargetSelection,
}

impl std::fmt::Debug for ServerSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[S{} - {}]", self.id, self.remote_address)
    }
}

impl ServerSession {
    pub async fn new(
        remote_address: std::net::SocketAddr,
        state: Arc<Mutex<State>>,
    ) -> Arc<Mutex<Self>> {
        let (session_handle, mut session_handle_rx) = SSHSessionHandle::new();

        let session_state = Arc::new(Mutex::new(SessionState::new(
            remote_address,
            Box::new(session_handle),
        )));
        let id = state.lock().await.register_session(&session_state);

        let mut rc_handles = RemoteClient::create(id);

        let this = Self {
            id,
            session_handle: None,
            pty_channels: vec![],
            all_channels: vec![],
            rc_tx: rc_handles.command_tx.clone(),
            rc_abort_tx: rc_handles.abort_tx,
            rc_state: RCState::NotInitialized,
            remote_address,
            state,
            session_state,
            target: TargetSelection::None,
        };

        info!(session=?this, "New connection");

        let session_debug_tag = format!("{:?}", this);
        let this = Arc::new(Mutex::new(this));

        let name = format!("SSH S{} session control", id);
        tokio::task::Builder::new().name(&name).spawn({
            let session_debug_tag = session_debug_tag.clone();
            let this = Arc::downgrade(&this);
            async move {
                loop {
                    let state = session_handle_rx.recv().await;
                    match state {
                        Some(c) => {
                            debug!(session=%session_debug_tag, command=?c, "Session control");
                            let Some(this) = this.upgrade() else {
                                break;
                            };
                            let this = &mut this.lock().await;
                            if let Err(err) = this.handle_session_control(c).await {
                                error!(session=%session_debug_tag, "Event handler error: {:?}", err);
                                break;
                            }
                        }
                        None => {
                            break;
                        }
                    }
                }
                debug!(session=%session_debug_tag, "No more session control commands");
            }
        });

        let name = format!("SSH S{} client events", id);
        tokio::task::Builder::new().name(&name).spawn({
            let this = Arc::downgrade(&this);
            async move {
                loop {
                    let state = rc_handles.event_rx.recv().await;
                    match state {
                        Some(e) => {
                            debug!(session=%session_debug_tag, event=?e, "Event");
                            let Some(this) = this.upgrade() else {
                                break;
                            };
                            let this = &mut this.lock().await;
                            match e {
                                RCEvent::Done => break,
                                e => {
                                    if let Err(err) = this.handle_remote_event(e).await {
                                        error!(session=%session_debug_tag, "Event handler error: {:?}", err);
                                        break;
                                    }
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
        let channels = self.pty_channels.clone();
        for channel in channels {
            let _ = self
                .maybe_with_session(|session| async {
                    let _ = session.data(channel.0, CryptoVec::from_slice(data)).await;
                    Ok(())
                })
                .await;
        }
    }

    pub async fn maybe_connect_remote(&mut self) -> Result<()> {
        match self.target.clone() {
            TargetSelection::None => {
                panic!("Target not set");
            }
            TargetSelection::NotFound(name) => {
                self.emit_service_message(&format!("Selected target not found: {name}"))
                    .await;
                self.disconnect_server().await;
                anyhow::bail!("Target not found: {}", name);
            }
            TargetSelection::Found(snapshot) => {
                if self.rc_state == RCState::NotInitialized {
                    self.rc_state = RCState::Connecting;
                    let address_str = format!("{}:{}", snapshot.host, snapshot.port);
                    match address_str
                        .to_socket_addrs()
                        .map_err(|e| anyhow::anyhow!("{}", e))
                        .and_then(|mut x| x.next().ok_or(anyhow::anyhow!("Cannot resolve address")))
                    {
                        Ok(address) => {
                            self.rc_tx.send(RCCommand::Connect(address))?;
                            self.emit_service_message(&format!("Connecting to {address}"))
                                .await;
                        }
                        Err(error) => {
                            error!(session=?self, ?error, "Cannot find target address");
                            self.emit_service_message(&format!(
                                "Could not resolve target address {address_str}"
                            ))
                            .await;
                            self.disconnect_server().await;
                            Err(error)?
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn handle_session_control(&mut self, command: SessionHandleCommand) -> Result<()> {
        match command {
            SessionHandleCommand::Close => {
                let _ = self.emit_service_message("Session closed by admin").await;
                info!(session=?self, "Session closed by admin");
                let _ = self.request_disconnect().await;
                self.disconnect_server().await;
            }
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
                        self.disconnect_server().await;
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
        Ok(())
    }

    pub async fn _window_change_request(&mut self, channel: ServerChannelId, request: PtyRequest) {
        self.send_command(RCCommand::Channel(
            channel,
            ChannelOperation::ResizePty(request),
        ));
    }

    pub async fn _channel_exec_request(
        &mut self,
        channel: ServerChannelId,
        data: Bytes,
    ) -> Result<()> {
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
        let _ = self.maybe_connect_remote().await;
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
        key: &PublicKey,
    ) -> thrussh::server::Auth {
        info!(session=?self, "Public key auth as {} with key FP {}", user, key.fingerprint());
        let selector: Selector = user[..].into();
        let user = {
            let state = self.state.lock().await;
            state
                .config
                .users
                .iter()
                .find(|x| x.username == selector.username)
                .map(User::to_owned)
        };
        let Some(user) = user else {
            self.emit_service_message(&format!("Selected user not found: {}", selector.username)).await;
            return thrussh::server::Auth::Reject;
        };

        let UserAuth::PublicKey { key: ref user_key } = user.auth else {
            return thrussh::server::Auth::Reject;
        };

        let client_key = format!("{} {}", key.name(), key.public_key_base64());
        debug!(session=?self, "Client key: {}", client_key);

        if &client_key != user_key {
            error!(session=?self, "Client key does not match");
            return thrussh::server::Auth::Reject;
        }

        self._auth_accept(user, selector).await
    }

    async fn _auth_accept(&mut self, user: User, selector: Selector) -> thrussh::server::Auth {
        info!(session=?self, "Authenticated");

        let state = self.state.lock().await;
        let target = state
            .config
            .targets
            .iter()
            .find(|x| x.name == selector.target_name);

        let Some(target) = target else {
            self.target = TargetSelection::NotFound(selector.target_name);
            info!(session=?self, "Selected target not found");
            return thrussh::server::Auth::Accept;
        };

        let mut session_state = self.session_state.lock().await;
        session_state.user = Some(user);
        session_state.target = Some(target.clone());
        self.target = TargetSelection::Found(target.clone());
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

    async fn disconnect_server(&mut self) {
        let channels: Vec<ServerChannelId> = self.all_channels.drain(..).collect();
        let _ = self
            .maybe_with_session(|handle| async move {
                for ch in channels {
                    let _ = handle.close(ch.0).await;
                }
                Ok(())
            })
            .await;
        drop(self.session_handle.take());
    }
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
