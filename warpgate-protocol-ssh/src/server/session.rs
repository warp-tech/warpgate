use super::session_handle::SessionHandleCommand;
use crate::compat::ContextExt;
use crate::{
    ChannelOperation, ConnectionError, DirectTCPIPParams, PtyRequest, RCCommand, RCEvent, RCState,
    RemoteClient, ServerChannelId,
};
use ansi_term::Colour;
use anyhow::Result;
use bytes::{Bytes, BytesMut};
use russh::server::Session;
use russh::{CryptoVec, Sig};
use russh_keys::key::PublicKey;
use russh_keys::PublicKeyBase64;
use std::collections::hash_map::Entry::Vacant;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::{oneshot, Mutex};
use tracing::*;
use warpgate_common::auth::AuthSelector;
use warpgate_common::eventhub::{EventHub, EventSender};
use warpgate_common::recordings::{
    ConnectionRecorder, TerminalRecorder, TrafficConnectionParams, TrafficRecorder,
};
use warpgate_common::{
    authorize_ticket, AuthCredential, AuthResult, Secret, Services, SessionId, Target,
    TargetSSHOptions, WarpgateServerHandle,
};

#[derive(Clone)]
enum TargetSelection {
    None,
    NotFound(String),
    Found(Target, TargetSSHOptions),
}

#[derive(Debug)]
enum Event {
    ConsoleInput(Bytes),
    Client(RCEvent),
}

pub struct ServerSession {
    pub id: SessionId,
    session_handle: Option<russh::server::Handle>,
    pty_channels: Vec<ServerChannelId>,
    all_channels: Vec<ServerChannelId>,
    channel_recorders: HashMap<ServerChannelId, TerminalRecorder>,
    rc_tx: UnboundedSender<RCCommand>,
    rc_abort_tx: UnboundedSender<()>,
    rc_state: RCState,
    remote_address: SocketAddr,
    services: Services,
    server_handle: WarpgateServerHandle,
    target: TargetSelection,
    traffic_recorders: HashMap<(String, u32), TrafficRecorder>,
    traffic_connection_recorders: HashMap<ServerChannelId, ConnectionRecorder>,
    credentials: Vec<AuthCredential>,
    hub: EventHub<Event>,
    event_sender: EventSender<Event>,
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
        let mut rc_handles = RemoteClient::create(
            id,
            session_debug_tag(&id, &remote_address),
            services.clone(),
        );

        let (hub, event_sender) = EventHub::setup();
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
            hub,
            event_sender,
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
                    let Some(command) = session_handle_rx.recv().await else {
                        break;
                    };
                    debug!(session=%session_debug_tag, ?command, "Session control");
                    let Some(this) = this.upgrade() else {
                        break;
                    };
                    let this = &mut this.lock().await;
                    if let Err(err) = this.handle_session_control(command).await {
                        error!(session=%session_debug_tag, "Event handler error: {:?}", err);
                        break;
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
                    let Some(e) = rc_handles.event_rx.recv().await else {
                        break
                    };
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
                msg.replace("\n", "\r\n"),
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
            TargetSelection::Found(target, ssh_options) => {
                if self.rc_state == RCState::NotInitialized {
                    self.rc_state = RCState::Connecting;
                    self.rc_tx.send(RCCommand::Connect(ssh_options))?;
                    self.emit_service_message(&format!("Connecting to {}", target.name))
                        .await;
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
                        self.emit_service_message("Connected").await;
                    }
                    RCState::Disconnected => {
                        self.disconnect_server().await;
                    }
                    _ => {}
                }
            }
            RCEvent::ConnectionError(error) => match error {
                ConnectionError::HostKeyMismatch {
                    received_key_type,
                    received_key_base64,
                    known_key_type,
                    known_key_base64,
                } => {
                    let msg = format!(
                        concat!(
                            "Host key doesn't match the stored one.\n",
                            "Stored key   ({}): {}\n",
                            "Received key ({}): {}",
                        ),
                        known_key_type, known_key_base64, received_key_type, received_key_base64
                    );
                    self.emit_service_message(&msg).await;
                    self.emit_service_message(
                        "If you know that the key is correct (e.g. it has been changed),",
                    )
                    .await;
                    self.emit_service_message(
                        "you can remove the old key in the Warpgate management UI and try again",
                    )
                    .await;
                }
                error => {
                    self.emit_service_message(&format!("Connection failed: {}", error))
                        .await;
                }
            },
            RCEvent::AuthError => {
                self.emit_service_message("Authentication failed").await;
            }
            RCEvent::Output(channel, data) => {
                if let Some(recorder) = self.channel_recorders.get_mut(&channel) {
                    if let Err(error) = recorder.write(&data).await {
                        error!(session=?self, %channel, ?error, "Failed to record terminal data");
                        self.channel_recorders.remove(&channel);
                    }
                }

                if let Some(recorder) = self.traffic_connection_recorders.get_mut(&channel) {
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
                if let Some(recorder) = self.channel_recorders.get_mut(&channel) {
                    if let Err(error) = recorder.write(&data).await {
                        error!(session=?self, %channel, ?error, "Failed to record session data");
                        self.channel_recorders.remove(&channel);
                    }
                }
                self.maybe_with_session(|handle| async move {
                    handle
                        .extended_data(channel.0, ext, CryptoVec::from_slice(&data))
                        .await
                        .map_err(|_| ())
                        .context("failed to send extended data")?;
                    Ok(())
                })
                .await?;
            }
            RCEvent::HostKeyReceived(key) => {
                self.emit_service_message(&format!(
                    "Host key ({}): {}",
                    key.name(),
                    key.public_key_base64()
                ))
                .await;
            }
            RCEvent::HostKeyUnknown(key, reply) => {
                self.handle_unknown_host_key(key, reply).await?;
            }
        }
        Ok(())
    }

    async fn handle_unknown_host_key(
        &mut self,
        key: PublicKey,
        reply: oneshot::Sender<bool>,
    ) -> Result<()> {
        //self.emit_service_message(&format!("Host key ({}): {}", key.name(), key.public_key_base64())).await;
        self.emit_service_message(&format!(
            "There is no trusted {} key for this host.",
            key.name()
        ))
        .await;
        self.emit_service_message(&"Trust this key? (y/n)")
            .await;

        let mut sub = self
            .hub
            .subscribe(|e| matches!(e, Event::ConsoleInput(_)))
            .await;
        tokio::spawn(async move {
            loop {
                match sub.recv().await {
                    Some(Event::ConsoleInput(data)) => {
                        if data == "y".as_bytes() {
                            let _ = reply.send(true);
                            break;
                        } else if data == "n".as_bytes() {
                            let _ = reply.send(false);
                            break;
                        }
                    }
                    None => break,
                    _ => (),
                }
            }
        });

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
            .traffic_recorder_for(&params.host_to_connect, params.port_to_connect)
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

    pub fn _channel_env_request(&mut self, channel: ServerChannelId, name: String, value: String) {
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
        if let Vacant(e) = self.traffic_recorders.entry((host.clone(), port)) {
            match self
                .services
                .recordings
                .lock()
                .await
                .start(&self.id, format!("direct-tcpip-{host}-{port}"))
                .await
            {
                Ok(recorder) => {
                    e.insert(recorder);
                }
                Err(error) => {
                    error!(session=?self, %host, %port, ?error, "Failed to start recording");
                }
            }
        }
        self.traffic_recorders.get_mut(&(host.clone(), port))
    }

    pub async fn _channel_shell_request(&mut self, channel: ServerChannelId) -> Result<()> {
        self.rc_tx
            .send(RCCommand::Channel(channel, ChannelOperation::RequestShell))?;

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

    pub async fn _channel_subsystem_request(&mut self, channel: ServerChannelId, name: String) {
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

        if let Some(recorder) = self.traffic_connection_recorders.get_mut(&channel) {
            if let Err(error) = recorder.write_tx(&data).await {
                error!(session=?self, %channel, ?error, "Failed to record traffic data");
                self.traffic_connection_recorders.remove(&channel);
            }
        }

        if self.pty_channels.contains(&channel) {
            let _ = self
                .event_sender
                .send_once(Event::ConsoleInput(data.clone()))
                .await;
        }

        self.send_command(RCCommand::Channel(channel, ChannelOperation::Data(data)));
    }

    pub async fn _extended_data(&mut self, channel: ServerChannelId, code: u32, data: BytesMut) {
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
        ssh_username: String,
        key: &PublicKey,
    ) -> russh::server::Auth {
        let selector: AuthSelector = (&ssh_username).into();

        info!(session=?self, "Public key auth as {:?} with key FP {}", selector, key.fingerprint());

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
        ssh_username: Secret<String>,
        password: Secret<String>,
    ) -> russh::server::Auth {
        let selector: AuthSelector = ssh_username.expose_secret().into();
        info!(session=?self, "Password key auth as {:?}", selector);

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

    async fn try_auth(&mut self, selector: &AuthSelector) -> Result<AuthResult> {
        match selector {
            AuthSelector::User {
                username,
                target_name,
            } => {
                let user_auth_result: AuthResult = {
                    self.services
                        .config_provider
                        .lock()
                        .await
                        .authorize(username, &self.credentials)
                        .await?
                };

                match user_auth_result {
                    AuthResult::Accepted { username } => {
                        let target_auth_result = {
                            self.services
                                .config_provider
                                .lock()
                                .await
                                .authorize_target(&username, target_name)
                                .await?
                        };
                        if !target_auth_result {
                            warn!(
                                "Target {} not authorized for user {}",
                                target_name, username
                            );
                            return Ok(AuthResult::Rejected);
                        }
                        self._auth_accept(&username, target_name).await;
                        Ok(AuthResult::Accepted { username })
                    }
                    AuthResult::Rejected => Ok(AuthResult::Rejected),
                }
            }
            AuthSelector::Ticket { secret } => {
                match authorize_ticket(&self.services.db, secret).await? {
                    Some(ticket) => {
                        info!(session=?self, "Authorized for {} with a ticket", ticket.target);
                        self.services
                            .config_provider
                            .lock()
                            .await
                            .consume_ticket(&ticket.id)
                            .await?;
                        self._auth_accept(&ticket.username, &ticket.target).await;
                        Ok(AuthResult::Accepted {
                            username: ticket.username.clone(),
                        })
                    }
                    None => Ok(AuthResult::Rejected),
                }
            }
        }
    }

    async fn _auth_accept(&mut self, username: &str, target_name: &str) {
        info!(session=?self, "Authenticated");

        let _ = self.server_handle.set_username(username.to_string()).await;

        let target = {
            self.services
                .config
                .lock()
                .await
                .store
                .targets
                .iter()
                .find(|x| x.name == target_name)
                .filter(|x| x.ssh.is_some())
                .map(|x| (x.clone(), x.ssh.clone().unwrap()))
        };

        let Some((target, ssh_options)) = target else {
            self.target = TargetSelection::NotFound(target_name.to_string());
            info!(session=?self, "Selected target not found");
            return;
        };

        let _ = self.server_handle.set_target(&target).await;
        self.target = TargetSelection::Found(target, ssh_options);
    }

    pub async fn _channel_close(&mut self, channel: ServerChannelId) {
        debug!(session=?self, %channel, "Closing channel");
        self.send_command(RCCommand::Channel(channel, ChannelOperation::Close));
    }

    pub async fn _channel_eof(&mut self, channel: ServerChannelId) {
        debug!(session=?self, %channel, "EOF");
        self.send_command(RCCommand::Channel(channel, ChannelOperation::Eof));
    }

    pub async fn _channel_signal(&mut self, channel: ServerChannelId, signal: Sig) {
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
        let _ = self.rc_abort_tx.send(());
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
        info!(session=?self, "Closed connection");
        debug!("Dropped");
    }
}
