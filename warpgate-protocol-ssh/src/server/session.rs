use super::super::{
    ChannelOperation, PtyRequest, RCCommand, RCEvent, RCState, RemoteClient,
    ServerChannelId,
};
use super::session_handle::SessionHandleCommand;
use crate::compat::ContextExt;
use crate::DirectTCPIPParams;
use ansi_term::Colour;
use anyhow::Result;
use bytes::{Bytes, BytesMut};
use russh::server::Session;
use russh::{CryptoVec, Sig};
use russh_keys::key::PublicKey;
use russh_keys::PublicKeyBase64;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::{oneshot, Mutex};
use tracing::*;
use warpgate_common::recordings::{
    ConnectionRecorder, TerminalRecorder, TrafficConnectionParams,
    TrafficRecorder,
};
use warpgate_common::{
    AuthCredential, AuthResult, Services, SessionId, Target,
    WarpgateServerHandle,
};

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
    pub id: SessionId,
    session_handle: Option<russh::server::Handle>,
    pty_channels: Vec<ServerChannelId>,
    all_channels: Vec<ServerChannelId>,
    channel_recorders: HashMap<ServerChannelId, TerminalRecorder>,
    rc_tx: UnboundedSender<RCCommand>,
    rc_abort_tx: Option<oneshot::Sender<()>>,
    rc_state: RCState,
    remote_address: SocketAddr,
    services: Services,
    server_handle: WarpgateServerHandle,
    target: TargetSelection,
    traffic_recorders: HashMap<(String, u32), TrafficRecorder>,
    traffic_connection_recorders: HashMap<ServerChannelId, ConnectionRecorder>,
    credentials: Vec<AuthCredential>,
}

fn session_debug_tag(id: &SessionId, remote_address: &SocketAddr) -> String {
    format!("[{} - {}]", id, remote_address)
}

impl std::fmt::Debug for ServerSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", session_debug_tag(&self.id, &self.remote_address))
    }
}

impl ServerSession {
    pub async fn new(
        remote_address: SocketAddr,
        services: &Services,
        server_handle: WarpgateServerHandle,
        mut session_handle_rx: UnboundedReceiver<SessionHandleCommand>,
    ) -> Result<Arc<Mutex<Self>>> {
        let id = server_handle.id();
        let mut rc_handles =
            RemoteClient::create(id, session_debug_tag(&id, &remote_address));

        let this = Self {
            id: server_handle.id(),
            session_handle: None,
            pty_channels: vec![],
            all_channels: vec![],
            channel_recorders: HashMap::new(),
            rc_tx: rc_handles.command_tx.clone(),
            rc_abort_tx: rc_handles.abort_tx,
            rc_state: RCState::NotInitialized,
            remote_address,
            services: services.clone(),
            server_handle,
            target: TargetSelection::None,
            traffic_recorders: HashMap::new(),
            traffic_connection_recorders: HashMap::new(),
            credentials: vec![],
        };

        info!(session=?this, "New connection");

        let session_debug_tag = format!("{:?}", this);
        let this = Arc::new(Mutex::new(this));

        let name = format!("SSH {} session control", id);
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

        let name = format!("SSH {} client events", id);
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

        Ok(this)
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
                    let _ = session
                        .data(channel.0, CryptoVec::from_slice(data))
                        .await;
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
                self.emit_service_message(&format!(
                    "Selected target not found: {name}"
                ))
                .await;
                self.disconnect_server().await;
                anyhow::bail!("Target not found: {}", name);
            }
            TargetSelection::Found(snapshot) => {
                if self.rc_state == RCState::NotInitialized {
                    self.rc_state = RCState::Connecting;
                    let address_str =
                        format!("{}:{}", snapshot.host, snapshot.port);
                    match address_str
                        .to_socket_addrs()
                        .map_err(|e| anyhow::anyhow!("{}", e))
                        .and_then(|mut x| {
                            x.next().ok_or(anyhow::anyhow!(
                                "Cannot resolve address"
                            ))
                        }) {
                        Ok(address) => {
                            self.rc_tx.send(RCCommand::Connect(address))?;
                            self.emit_service_message(&format!(
                                "Connecting to {address}"
                            ))
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

    pub async fn handle_session_control(
        &mut self,
        command: SessionHandleCommand,
    ) -> Result<()> {
        match command {
            SessionHandleCommand::Close => {
                let _ =
                    self.emit_service_message("Session closed by admin").await;
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
                if let Some(recorder) = self.channel_recorders.get_mut(&channel)
                {
                    if let Err(error) = recorder.write(&data).await {
                        error!(session=?self, %channel, ?error, "Failed to record terminal data");
                        self.channel_recorders.remove(&channel);
                    }
                }

                if let Some(recorder) =
                    self.traffic_connection_recorders.get_mut(&channel)
                {
                    if let Err(error) = recorder.write_rx(&data).await {
                        error!(session=?self, %channel, ?error, "Failed to record traffic data");
                        self.traffic_connection_recorders.remove(&channel);
                    }
                }

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
                channel: channel_id,
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
            RCEvent::ExtendedData { channel, data, ext } => {
                if let Some(recorder) = self.channel_recorders.get_mut(&channel)
                {
                    if let Err(error) = recorder.write(&data).await {
                        error!(session=?self, %channel, ?error, "Failed to record session data");
                        self.channel_recorders.remove(&channel);
                    }
                }
                self.maybe_with_session(|handle| async move {
                    handle
                        .extended_data(
                            channel.0,
                            ext,
                            CryptoVec::from_slice(&data),
                        )
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
        FN: FnOnce(&'a mut russh::server::Handle) -> FT + 'a,
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
        info!(session=?self, %channel, "Opening session channel");
        self.all_channels.push(channel);
        self.session_handle = Some(session.handle());
        self.rc_tx
            .send(RCCommand::Channel(channel, ChannelOperation::OpenShell))?;
        Ok(())
    }

    pub async fn _channel_open_direct_tcpip(
        &mut self,
        channel: ServerChannelId,
        params: DirectTCPIPParams,
        session: &mut Session,
    ) -> Result<()> {
        info!(session=?self, %channel, "Opening direct TCP/IP channel from {}:{} to {}:{}", params.originator_address, params.originator_port, params.host_to_connect, params.port_to_connect);

        let recorder = self
            .traffic_recorder_for(
                &params.host_to_connect,
                params.port_to_connect,
            )
            .await;
        if let Some(recorder) = recorder {
            let mut recorder = recorder.connection(TrafficConnectionParams {
                dst_addr: Ipv4Addr::from_str("2.2.2.2").unwrap(),
                dst_port: params.port_to_connect as u16,
                src_addr: Ipv4Addr::from_str("1.1.1.1").unwrap(),
                src_port: params.originator_port as u16,
            });
            if let Err(error) = recorder.write_connection_setup().await {
                error!(session=?self, %channel, ?error, "Failed to record connection setup");
            }
            self.traffic_connection_recorders.insert(channel, recorder);
        }

        self.all_channels.push(channel);
        self.session_handle = Some(session.handle());
        self.rc_tx.send(RCCommand::Channel(
            channel,
            ChannelOperation::OpenDirectTCPIP(params),
        ))?;
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

    pub async fn _window_change_request(
        &mut self,
        channel: ServerChannelId,
        request: PtyRequest,
    ) {
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
                error!(session=?self, channel=%channel.0, ?data, "Requested exec - invalid UTF-8");
                anyhow::bail!(e)
            }
            Ok::<&str, _>(command) => {
                debug!(session=?self, channel=%channel.0, %command, "Requested exec");
                let _ = self.maybe_connect_remote().await;
                self.send_command(RCCommand::Channel(
                    channel,
                    ChannelOperation::RequestExec(command.to_string()),
                ));
            }
        }
        Ok(())
    }

    pub fn _channel_env_request(
        &mut self,
        channel: ServerChannelId,
        name: String,
        value: String,
    ) {
        debug!(session=?self, %channel, %name, %value, "Environment");
        self.send_command(RCCommand::Channel(
            channel,
            ChannelOperation::RequestEnv(name, value),
        ));
    }

    async fn traffic_recorder_for(
        &mut self,
        host: &String,
        port: u32,
    ) -> Option<&mut TrafficRecorder> {
        if !self.traffic_recorders.contains_key(&(host.clone(), port)) {
            match self
                .services
                .recordings
                .lock()
                .await
                .start(&self.id, format!("direct-tcpip-{host}-{port}"))
                .await
            {
                Ok(recorder) => {
                    self.traffic_recorders
                        .insert((host.clone(), port), recorder);
                }
                Err(error) => {
                    error!(session=?self, %host, %port, ?error, "Failed to start recording");
                }
            }
        }
        self.traffic_recorders.get_mut(&(host.clone(), port))
    }

    pub async fn _channel_shell_request(
        &mut self,
        channel: ServerChannelId,
    ) -> Result<()> {
        self.rc_tx.send(RCCommand::Channel(
            channel,
            ChannelOperation::RequestShell,
        ))?;

        match self
            .services
            .recordings
            .lock()
            .await
            .start(&self.id, format!("shell-channel-{}", channel.0))
            .await
        {
            Ok(recorder) => {
                self.channel_recorders.insert(channel, recorder);
            }
            Err(error) => {
                error!(session=?self, %channel, ?error, "Failed to start recording");
            }
        }

        info!(session=?self, %channel, "Opening shell");
        let _ = self
            .session_handle
            .as_mut()
            .unwrap()
            .channel_success(channel.0)
            .await;
        let _ = self.maybe_connect_remote().await;
        Ok(())
    }

    pub async fn _channel_subsystem_request(
        &mut self,
        channel: ServerChannelId,
        name: String,
    ) {
        info!(session=?self, %channel, "Requesting subsystem {}", &name);
        self.send_command(RCCommand::Channel(
            channel,
            ChannelOperation::RequestSubsystem(name),
        ));
    }

    pub async fn _data(&mut self, channel: ServerChannelId, data: Bytes) {
        debug!(session=?self, channel=%channel.0, ?data, "Data");
        if self.rc_state == RCState::Connecting && data.get(0) == Some(&3) {
            info!(session=?self, %channel, "User requested connection abort (Ctrl-C)");
            self.request_disconnect().await;
            return;
        }

        if let Some(recorder) =
            self.traffic_connection_recorders.get_mut(&channel)
        {
            if let Err(error) = recorder.write_tx(&data).await {
                error!(session=?self, %channel, ?error, "Failed to record traffic data");
                self.traffic_connection_recorders.remove(&channel);
            }
        }

        self.send_command(RCCommand::Channel(
            channel,
            ChannelOperation::Data(data),
        ));
    }

    pub async fn _extended_data(
        &mut self,
        channel: ServerChannelId,
        code: u32,
        data: BytesMut,
    ) {
        debug!(session=?self, channel=%channel.0, ?data, "Data");
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
    ) -> russh::server::Auth {
        let selector: Selector = user[..].into();

        info!(session=?self, "Public key auth as {} with key FP {}", selector.username, key.fingerprint());

        self.credentials.push(AuthCredential::PublicKey {
            kind: key.name().to_string(),
            public_key_bytes: Bytes::from(key.public_key_bytes()),
        });

        match self.try_auth(&selector).await {
            Ok(AuthResult::Accepted { .. }) => russh::server::Auth::Accept,
            Ok(AuthResult::Rejected) => russh::server::Auth::Reject,
            Err(error) => {
                error!(session=?self, ?error, "Failed to verify credentials");
                russh::server::Auth::Reject
            }
        }
    }

    pub async fn _auth_password(
        &mut self,
        username: String,
        password: String,
    ) -> russh::server::Auth {
        let selector: Selector = username[..].into();
        info!(session=?self, "Password key auth as {}", selector.username);

        self.credentials.push(AuthCredential::Password(password));

        match self.try_auth(&selector).await {
            Ok(AuthResult::Accepted { .. }) => russh::server::Auth::Accept,
            Ok(AuthResult::Rejected) => russh::server::Auth::Reject,
            Err(error) => {
                error!(session=?self, ?error, "Failed to verify credentials");
                russh::server::Auth::Reject
            }
        }
    }

    async fn try_auth(&mut self, selector: &Selector) -> Result<AuthResult> {
        let user_auth_result = {
            self.services
                .config_provider
                .lock()
                .await
                .authorize(&selector.username, &self.credentials)
                .await
        };
        match user_auth_result? {
            AuthResult::Accepted {
                username,
                via_ticket,
            } => {
                let target_name: &str;
                let target_auth_result = if let Some(ref ticket) = via_ticket {
                    self.services
                        .config_provider
                        .lock()
                        .await
                        .consume_ticket(&ticket.id)
                        .await?;
                    info!(session=?self, "Authorized for {} with a ticket", ticket.target);
                    target_name = &ticket.target;
                    true
                } else {
                    target_name = &selector.target_name;
                    self
                        .services
                        .config_provider
                        .lock()
                        .await
                        .authorize_target(&username, &selector.target_name)
                        .await?
                };

                if target_auth_result {
                    self._auth_accept(&username, target_name).await;
                    Ok(AuthResult::Accepted {
                        username,
                        via_ticket,
                    })
                } else {
                    warn!(
                        "Target {} not authorized for user {}",
                        selector.target_name, username
                    );
                    Ok(AuthResult::Rejected)
                }
            }
            AuthResult::Rejected => Ok(AuthResult::Rejected),
        }
    }

    async fn _auth_accept(&mut self, username: &str, target_name: &str) {
        info!(session=?self, "Authenticated");

        let target = {
            self.services
                .config
                .lock()
                .await
                .targets
                .iter()
                .find(|x| x.name == target_name)
                .map(Target::clone)
        };

        let _ = self.server_handle.set_username(username.to_string()).await;
        let Some(target) = target else {
            self.target = TargetSelection::NotFound(target_name.to_string());
            info!(session=?self, "Selected target not found");
            return;
        };

        let _ = self.server_handle.set_target(&target).await;
        self.target = TargetSelection::Found(target);
    }

    pub async fn _channel_close(&mut self, channel: ServerChannelId) {
        debug!(session=?self, %channel, "Closing channel");
        self.send_command(RCCommand::Channel(channel, ChannelOperation::Close));
    }

    pub async fn _channel_eof(&mut self, channel: ServerChannelId) {
        debug!(session=?self, %channel, "EOF");
        self.send_command(RCCommand::Channel(channel, ChannelOperation::Eof));
    }

    pub async fn _channel_signal(
        &mut self,
        channel: ServerChannelId,
        signal: Sig,
    ) {
        debug!(session=?self, %channel, ?signal, "Signal");
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
        if self.rc_state != RCState::NotInitialized
            && self.rc_state != RCState::Disconnected
        {
            self.send_command(RCCommand::Disconnect);
        }
    }

    async fn disconnect_server(&mut self) {
        let channels: Vec<ServerChannelId> =
            self.all_channels.drain(..).collect();
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
        info!(session=?self, "Closed connection");
        debug!("Dropped");
    }
}
