use std::borrow::Cow;
use std::collections::hash_map::Entry::Vacant;
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::Poll;

use ansi_term::Colour;
use anyhow::{Context, Result};
use bimap::BiMap;
use bytes::Bytes;
use futures::{Future, FutureExt};
use russh::keys::{PublicKey, PublicKeyBase64};
use russh::{CryptoVec, MethodKind, MethodSet, Sig};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::{broadcast, oneshot, Mutex};
use tracing::*;
use uuid::Uuid;
use warpgate_common::auth::{
    AuthCredential, AuthResult, AuthSelector, AuthState, AuthStateUserInfo, CredentialKind,
};
use warpgate_common::eventhub::{EventHub, EventSender, EventSubscription};
use warpgate_common::{
    Secret, SessionId, SshHostKeyVerificationMode, Target, TargetOptions, TargetSSHOptions,
    WarpgateError,
};
use warpgate_core::recordings::{
    self, ConnectionRecorder, TerminalRecorder, TerminalRecordingStreamId, TrafficConnectionParams,
    TrafficRecorder,
};
use warpgate_core::{
    authorize_ticket, consume_ticket, ConfigProvider, FileTransferPermission, Services,
    WarpgateServerHandle,
};

use super::channel_writer::ChannelWriter;
use super::russh_handler::ServerHandlerEvent;
use super::service_output::ServiceOutput;
use super::session_handle::SessionHandleCommand;
use crate::compat::ContextExt;
use crate::server::get_allowed_auth_methods;
use crate::server::service_output::ERASE_PROGRESS_SPINNER;
use crate::sftp::{
    build_close_packet, build_denial_response, build_remove_packet, packet_to_operation,
    packet_to_response, FileTransferTracker, SftpFileOperation, SftpResponse, TransferComplete,
    TransferDirection,
};
use crate::{
    ChannelOperation, ConnectionError, DirectTCPIPParams, PtyRequest, RCCommand, RCCommandReply,
    RCEvent, RCState, RemoteClient, ServerChannelId, SshClientError, SshRecordingMetadata,
    X11Request,
};

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
enum TargetSelection {
    None,
    NotFound(String),
    Found(Target, TargetSSHOptions),
}

#[derive(Debug)]
enum Event {
    Command(SessionHandleCommand),
    ServerHandler(ServerHandlerEvent),
    ConsoleInput(Bytes),
    ServiceOutput(Bytes),
    Client(RCEvent),
}

enum KeyboardInteractiveState {
    None,
    OtpRequested,
    WebAuthRequested(broadcast::Receiver<AuthResult>),
}

struct CachedSuccessfulTicketAuth {
    ticket: Secret<String>,
    user_info: AuthStateUserInfo,
}

/// Pending SFTP open request (waiting for HANDLE response)
struct PendingOpen {
    path: String,
    direction: TransferDirection,
}

/// Result of SFTP access control check
enum SftpCheckResult {
    /// Buffer has incomplete packet — don't forward anything yet
    Pending,
    /// All parsed packets are allowed — forward these raw bytes to the target
    Allowed(Vec<u8>),
    /// An operation was denied — send this error response to the client
    Denied(u32, String),
}

/// SFTP channel state for tracking file transfers
struct SftpChannelState {
    /// Pending OPEN requests: request_id -> (path, direction)
    pending_opens: HashMap<u32, PendingOpen>,
    /// Pending READ requests: request_id -> handle (to associate DATA responses)
    pending_reads: HashMap<u32, Vec<u8>>,
    /// File transfer tracker for hash calculation
    tracker: FileTransferTracker,
    /// Reassembly buffer for client -> server SFTP packets (for parsing)
    client_buf: Vec<u8>,
    /// Raw bytes waiting to be forwarded (mirrors client_buf, drained when packets are allowed)
    pending_forward: Vec<u8>,
    /// Reassembly buffer for server -> client SFTP packets
    server_buf: Vec<u8>,
    /// Handles that have been denied (suppress repeated log entries)
    denied_handles: HashSet<Vec<u8>>,
    /// Partial files to clean up on the server: (path, handle_string)
    pending_cleanup: Vec<(String, String)>,
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub enum TrafficRecorderKey {
    Tcp(String, u32),
    Socket(String),
}

pub struct ServerSession {
    pub id: SessionId,
    username: Option<String>,
    session_handle: Option<russh::server::Handle>,
    pty_channels: Vec<Uuid>,
    all_channels: Vec<Uuid>,
    channel_recorders: HashMap<Uuid, TerminalRecorder>,
    channel_map: BiMap<ServerChannelId, Uuid>,
    channel_pty_size_map: HashMap<Uuid, PtyRequest>,
    rc_tx: UnboundedSender<(RCCommand, Option<RCCommandReply>)>,
    rc_abort_tx: UnboundedSender<()>,
    rc_state: RCState,
    remote_address: SocketAddr,
    services: Services,
    server_handle: Arc<Mutex<WarpgateServerHandle>>,
    target: TargetSelection,
    traffic_recorders: HashMap<TrafficRecorderKey, TrafficRecorder>,
    traffic_connection_recorders: HashMap<Uuid, ConnectionRecorder>,
    hub: EventHub<Event>,
    event_sender: EventSender<Event>,
    main_event_subscription: EventSubscription<Event>,
    service_output: ServiceOutput,
    channel_writer: ChannelWriter,
    auth_state: Option<Arc<Mutex<AuthState>>>,
    keyboard_interactive_state: KeyboardInteractiveState,
    cached_successful_ticket_auth: Option<CachedSuccessfulTicketAuth>,
    allowed_auth_methods: MethodSet,
    /// File transfer permissions for the current session (fetched after auth)
    file_transfer_permission: Option<FileTransferPermission>,
    /// Channels that are SFTP subsystems (need packet inspection)
    sftp_channels: HashSet<Uuid>,
    /// SFTP channel state (pending opens, tracker) per channel
    sftp_channel_state: HashMap<Uuid, SftpChannelState>,
    /// Hash threshold in bytes (from config)
    hash_threshold: u64,
}

fn session_debug_tag(id: &SessionId, remote_address: &SocketAddr) -> String {
    format!("[{id} - {remote_address}]")
}

impl std::fmt::Debug for ServerSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", session_debug_tag(&self.id, &self.remote_address))
    }
}

impl ServerSession {
    pub async fn start(
        remote_address: SocketAddr,
        services: &Services,
        server_handle: Arc<Mutex<WarpgateServerHandle>>,
        mut session_handle_rx: UnboundedReceiver<SessionHandleCommand>,
        mut handler_event_rx: UnboundedReceiver<ServerHandlerEvent>,
    ) -> Result<impl Future<Output = Result<()>>> {
        let id = server_handle.lock().await.id();

        let _span = info_span!("SSH", session=%id);
        let _enter = _span.enter();

        let mut rc_handles = RemoteClient::create(id, services.clone())?;

        let (hub, event_sender) = EventHub::setup();
        let main_event_subscription = hub
            .subscribe(|e| !matches!(e, Event::ConsoleInput(_)))
            .await;

        let mut this = Self {
            id,
            username: None,
            session_handle: None,
            pty_channels: vec![],
            all_channels: vec![],
            channel_recorders: HashMap::new(),
            channel_map: BiMap::new(),
            channel_pty_size_map: HashMap::new(),
            rc_tx: rc_handles.command_tx.clone(),
            rc_abort_tx: rc_handles.abort_tx,
            rc_state: RCState::NotInitialized,
            remote_address,
            services: services.clone(),
            server_handle,
            target: TargetSelection::None,
            traffic_recorders: HashMap::new(),
            traffic_connection_recorders: HashMap::new(),
            hub,
            event_sender: event_sender.clone(),
            main_event_subscription,
            service_output: ServiceOutput::new(),
            channel_writer: ChannelWriter::new(),
            auth_state: None,
            keyboard_interactive_state: KeyboardInteractiveState::None,
            cached_successful_ticket_auth: None,
            allowed_auth_methods: get_allowed_auth_methods(services).await?,
            file_transfer_permission: None,
            sftp_channels: HashSet::new(),
            sftp_channel_state: HashMap::new(),
            hash_threshold: 10 * 1024 * 1024, // 10MB default, will be updated from config
        };

        let mut so_rx = this.service_output.subscribe();
        let so_sender = event_sender.clone();
        tokio::spawn(async move {
            loop {
                match so_rx.recv().await {
                    Ok(data) => {
                        if so_sender
                            .send_once(Event::ServiceOutput(data))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(_) => (),
                }
            }
        });

        let name = format!("SSH {id} session control");
        tokio::task::Builder::new().name(&name).spawn({
            let sender = event_sender.clone();
            async move {
                while let Some(command) = session_handle_rx.recv().await {
                    if sender.send_once(Event::Command(command)).await.is_err() {
                        break;
                    }
                }
            }
        })?;

        let name = format!("SSH {id} client events");
        tokio::task::Builder::new().name(&name).spawn({
            let sender = event_sender.clone();
            async move {
                while let Some(e) = rc_handles.event_rx.recv().await {
                    if sender.send_once(Event::Client(e)).await.is_err() {
                        break;
                    }
                }
            }
        })?;

        let name = format!("SSH {id} server handler events");
        tokio::task::Builder::new().name(&name).spawn({
            let sender: EventSender<Event> = event_sender.clone();
            async move {
                while let Some(e) = handler_event_rx.recv().await {
                    if sender.send_once(Event::ServerHandler(e)).await.is_err() {
                        break;
                    }
                }
            }
        })?;

        Ok(async move {
            while let Some(event) = this.get_next_event().await {
                this.handle_event(event).await?;
            }
            debug!("No more events");
            Ok::<_, anyhow::Error>(())
        })
    }

    async fn get_next_event(&mut self) -> Option<Event> {
        self.main_event_subscription.recv().await
    }

    async fn get_auth_state(&mut self, username: &str) -> Result<Arc<Mutex<AuthState>>> {
        #[allow(clippy::unwrap_used)]
        if self.auth_state.is_none()
            || self
                .auth_state
                .as_ref()
                .unwrap()
                .lock()
                .await
                .user_info()
                .username
                != username
        {
            let state = self
                .services
                .auth_state_store
                .lock()
                .await
                .create(
                    Some(&self.id),
                    username,
                    crate::PROTOCOL_NAME,
                    &[
                        CredentialKind::Password,
                        CredentialKind::PublicKey,
                        CredentialKind::Totp,
                        CredentialKind::WebUserApproval,
                    ],
                )
                .await?
                .1;
            self.auth_state = Some(state);
        }
        #[allow(clippy::unwrap_used)]
        Ok(self.auth_state.as_ref().cloned().unwrap())
    }

    pub fn make_logging_span(&self) -> tracing::Span {
        let client_ip = self.remote_address.ip().to_string();
        match self.username {
            Some(ref username) => {
                info_span!("SSH", session=%self.id, session_username=%username, %client_ip)
            }
            None => info_span!("SSH", session=%self.id, %client_ip),
        }
    }

    fn map_channel(&self, ch: &ServerChannelId) -> Result<Uuid, WarpgateError> {
        self.channel_map
            .get_by_left(ch)
            .cloned()
            .ok_or(WarpgateError::InconsistentState)
    }

    fn map_channel_reverse(&self, ch: &Uuid) -> Result<ServerChannelId> {
        self.channel_map
            .get_by_right(ch)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Channel not known"))
    }

    pub async fn emit_service_message(&mut self, msg: &str) -> Result<()> {
        debug!("Service message: {}", msg);

        self.service_output.emit_output(Bytes::from(format!(
            "{}{} {}\r\n",
            ERASE_PROGRESS_SPINNER,
            Colour::Black.on(Colour::White).paint(" Warpgate "),
            msg.replace('\n', "\r\n"),
        )));

        Ok(())
    }

    pub async fn emit_pty_output(&mut self, data: &[u8]) -> Result<()> {
        let channels = self.pty_channels.clone();
        for channel in channels {
            let channel = self.map_channel_reverse(&channel)?;
            if let Some(session) = self.session_handle.clone() {
                self.channel_writer
                    .write(session, channel.0, CryptoVec::from_slice(data));
            }
        }
        Ok(())
    }

    /// Start connecting to the target if we aren't already.
    ///
    /// Timing of this call is important because if the client connection is
    /// an interactive session *in principle* (e.g a normal interactive OpenSSH
    /// session but maybe with some port forwards or agent)
    /// Ideally, it needs to be called by the time we already have the interactive
    /// channel open if we will ever have one to prevent bugs like
    /// https://github.com/warp-tech/warpgate/issues/1286
    /// where a PTY channel is required for the host key prompt, but we've connected
    /// faster than the client could open one.
    pub async fn maybe_connect_remote(&mut self) -> Result<()> {
        match self.target.clone() {
            TargetSelection::None => {
                anyhow::bail!("Invalid session state (target not set)")
            }
            TargetSelection::NotFound(name) => {
                self.emit_service_message(&format!("Selected target not found: {name}"))
                    .await?;
                self.disconnect_server().await;
                anyhow::bail!("Target not found: {name}");
            }
            TargetSelection::Found(target, ssh_options) => {
                if self.rc_state == RCState::NotInitialized {
                    self.connect_remote(target, ssh_options).await?;
                }
            }
        }
        Ok(())
    }

    async fn connect_remote(
        &mut self,
        target: Target,
        ssh_options: TargetSSHOptions,
    ) -> Result<()> {
        self.rc_state = RCState::Connecting;
        self.send_command(RCCommand::Connect(ssh_options))
            .map_err(|_| anyhow::anyhow!("cannot send command"))?;
        self.service_output.show_progress();
        self.emit_service_message(&format!("Selected target: {}", target.name))
            .await?;

        Ok(())
    }

    fn handle_event<'a>(
        &'a mut self,
        event: Event,
    ) -> Pin<Box<dyn Future<Output = Result<(), WarpgateError>> + Send + 'a>> {
        async move {
            match event {
                Event::Client(RCEvent::Done) => Err(WarpgateError::SessionEnd)?,
                Event::ServerHandler(ServerHandlerEvent::Disconnect) => {
                    Err(WarpgateError::SessionEnd)?
                }
                Event::Client(e) => {
                    debug!(event=?e, "Event");
                    let span = self.make_logging_span();
                    if let Err(err) = self.handle_remote_event(e).instrument(span).await {
                        error!("Client event handler error: {:?}", err);
                        // break;
                    }
                }
                Event::ServerHandler(e) => {
                    let span = self.make_logging_span();
                    if let Err(err) = self.handle_server_handler_event(e).instrument(span).await {
                        error!("Server event handler error: {:?}", err);
                        // break;
                    }
                }
                Event::Command(command) => {
                    debug!(?command, "Session control");
                    if let Err(err) = self.handle_session_control(command).await {
                        error!("Command handler error: {:?}", err);
                        // break;
                    }
                }
                Event::ServiceOutput(data) => {
                    let _ = self.emit_pty_output(&data).await;
                }
                Event::ConsoleInput(_) => (),
            }
            Ok(())
        }
        .boxed()
    }

    async fn handle_server_handler_event(&mut self, event: ServerHandlerEvent) -> Result<()> {
        match event {
            ServerHandlerEvent::Authenticated(handle) => {
                self.session_handle = Some(handle.0);
            }

            ServerHandlerEvent::ChannelOpenSession(server_channel_id, reply) => {
                let channel = Uuid::new_v4();
                self.channel_map.insert(server_channel_id, channel);

                info!(%channel, "Opening session channel");
                return match self
                    .send_command_and_wait(RCCommand::Channel(channel, ChannelOperation::OpenShell))
                    .await
                {
                    Ok(()) => {
                        self.all_channels.push(channel);
                        let _ = reply.send(true);
                        Ok(())
                    }
                    Err(SshClientError::Russh(russh::Error::ChannelOpenFailure(_))) => {
                        let _ = reply.send(false);
                        Ok(())
                    }
                    Err(x) => Err(x.into()),
                };
            }

            ServerHandlerEvent::SubsystemRequest(server_channel_id, name, reply) => {
                return match self
                    ._channel_subsystem_request(server_channel_id, name)
                    .await
                {
                    Ok(()) => {
                        let _ = reply.send(true);
                        Ok(())
                    }
                    Err(SshClientError::Russh(russh::Error::ChannelOpenFailure(_))) => {
                        let _ = reply.send(false);
                        Ok(())
                    }
                    Err(x) => Err(x.into()),
                }
            }

            ServerHandlerEvent::PtyRequest(server_channel_id, request, reply) => {
                let channel_id = self.map_channel(&server_channel_id)?;
                self.channel_pty_size_map
                    .insert(channel_id, request.clone());
                if let Some(recorder) = self.channel_recorders.get_mut(&channel_id) {
                    if let Err(error) = recorder
                        .write_pty_resize(request.col_width, request.row_height)
                        .await
                    {
                        error!(%channel_id, ?error, "Failed to record terminal data");
                        self.channel_recorders.remove(&channel_id);
                    }
                }
                self.send_command_and_wait(RCCommand::Channel(
                    channel_id,
                    ChannelOperation::RequestPty(request),
                ))
                .await?;
                let _ = self
                    .session_handle
                    .as_mut()
                    .context("Invalid session state")?
                    .channel_success(server_channel_id.0)
                    .await;
                self.pty_channels.push(channel_id);
                let _ = reply.send(());
            }

            ServerHandlerEvent::ShellRequest(server_channel_id, reply) => {
                let channel_id = self.map_channel(&server_channel_id)?;

                // Check if shell access is blocked
                if let Some(reason) = self.shell_block_reason().await {
                    info!(
                        event_type = "access_control",
                        action = "shell",
                        status = "denied",
                        denied_reason = %reason,
                        "Shell access denied"
                    );
                    // Accept the channel so we can send the Warpgate banner, then close
                    let _ = reply.send(true);
                    if let Some(ref mut session) = self.session_handle {
                        let banner = format!(
                            "\r\n\x1b[97;41m ✗ Access Denied \x1b[0m {reason}\r\n\r\n\
                             Only SFTP file transfers are permitted. Use an SFTP client to connect.\r\n\r\n"
                        );
                        let _ = session.extended_data(
                            server_channel_id.0,
                            1, // SSH_EXTENDED_DATA_STDERR
                            CryptoVec::from_slice(banner.as_bytes()),
                        ).await;
                        let _ = session.exit_status_request(server_channel_id.0, 1).await;
                        let _ = session.close(server_channel_id.0).await;
                    }
                    return Ok(());
                }

                let _ = self.maybe_connect_remote().await;

                let _ = self.send_command(RCCommand::Channel(
                    channel_id,
                    ChannelOperation::RequestShell,
                ));

                self.start_terminal_recording(
                    channel_id,
                    SshRecordingMetadata::Shell {
                        // HACK russh ChannelId is opaque except via Display
                        channel: server_channel_id.0.to_string().parse().unwrap_or_default(),
                    },
                )
                .await;

                info!(%channel_id, "Opening shell");

                let _ = self
                    .session_handle
                    .as_mut()
                    .context("Invalid session state")?
                    .channel_success(server_channel_id.0)
                    .await;

                let _ = reply.send(true);
            }

            ServerHandlerEvent::AuthPublicKey(username, key, reply) => {
                let _ = reply.send(self._auth_publickey(username, key).await);
            }

            ServerHandlerEvent::AuthPublicKeyOffer(username, key, reply) => {
                let _ = reply.send(self._auth_publickey_offer(username, key).await);
            }

            ServerHandlerEvent::AuthPassword(username, password, reply) => {
                let _ = reply.send(self._auth_password(username, password).await);
            }

            ServerHandlerEvent::AuthKeyboardInteractive(username, response, reply) => {
                let _ = reply.send(self._auth_keyboard_interactive(username, response).await);
            }

            ServerHandlerEvent::Data(channel, data, reply) => {
                self._data(channel, data).await?;
                let _ = reply.send(());
            }

            ServerHandlerEvent::ExtendedData(channel, data, code, reply) => {
                self._extended_data(channel, code, data).await?;
                let _ = reply.send(());
            }

            ServerHandlerEvent::ChannelClose(channel, reply) => {
                self._channel_close(channel).await?;
                let _ = reply.send(());
            }

            ServerHandlerEvent::ChannelEof(channel, reply) => {
                self._channel_eof(channel).await?;
                let _ = reply.send(());
            }

            ServerHandlerEvent::WindowChangeRequest(channel, request, reply) => {
                self._window_change_request(channel, request).await?;
                let _ = reply.send(());
            }

            ServerHandlerEvent::Signal(channel, signal, reply) => {
                self._channel_signal(channel, signal).await?;
                let _ = reply.send(());
            }

            ServerHandlerEvent::ExecRequest(server_channel_id, data, reply) => {
                // Check if exec access is blocked
                if let Some(reason) = self.shell_block_reason().await {
                    info!(
                        event_type = "access_control",
                        action = "exec",
                        status = "denied",
                        denied_reason = %reason,
                        "Command execution denied"
                    );
                    // Accept the channel so we can send stderr, then close with error exit status
                    let _ = reply.send(true);
                    if let Some(ref mut session) = self.session_handle {
                        let msg = format!(
                            "\x1b[97;41m ✗ Access Denied \x1b[0m {reason}\r\n\
                             Only SFTP file transfers are permitted.\r\n"
                        );
                        let _ = session.extended_data(
                            server_channel_id.0,
                            1, // SSH_EXTENDED_DATA_STDERR
                            CryptoVec::from_slice(msg.as_bytes()),
                        ).await;
                        let _ = session.exit_status_request(server_channel_id.0, 1).await;
                        let _ = session.close(server_channel_id.0).await;
                    }
                } else {
                    match self._channel_exec_request(server_channel_id, data).await {
                        Ok(()) => {
                            let _ = reply.send(true);
                        }
                        Err(e) => {
                            warn!(channel=?server_channel_id, error=%e, "Exec request denied");
                            let _ = reply.send(false);
                        }
                    }
                }
            }

            ServerHandlerEvent::ChannelOpenDirectTcpIp(channel, params, reply) => {
                // Check if port forwarding is blocked
                if let Some(reason) = self.shell_block_reason().await {
                    info!(
                        event_type = "access_control",
                        action = "direct_tcpip",
                        %channel,
                        status = "denied",
                        denied_reason = %reason,
                        target_host = %params.host_to_connect,
                        target_port = %params.port_to_connect,
                        "Direct TCP/IP forwarding denied"
                    );
                    let _ = reply.send(false);
                } else {
                    let _ = reply.send(self._channel_open_direct_tcpip(channel, params).await?);
                }
            }

            ServerHandlerEvent::ChannelOpenDirectStreamlocal(channel, path, reply) => {
                // Check if port forwarding is blocked
                if let Some(reason) = self.shell_block_reason().await {
                    info!(
                        event_type = "access_control",
                        action = "direct_streamlocal",
                        %channel,
                        status = "denied",
                        denied_reason = %reason,
                        socket_path = %path,
                        "Unix socket forwarding denied"
                    );
                    let _ = reply.send(false);
                } else {
                    let _ = reply.send(self._channel_open_direct_streamlocal(channel, path).await?);
                }
            }

            ServerHandlerEvent::EnvRequest(channel, name, value, reply) => {
                self._channel_env_request(channel, name, value).await?;
                let _ = reply.send(());
            }

            ServerHandlerEvent::X11Request(channel, request, reply) => {
                self._channel_x11_request(channel, request).await?;
                let _ = reply.send(());
            }

            ServerHandlerEvent::TcpIpForward(address, port, reply) => {
                // Check if port forwarding is blocked
                if let Some(reason) = self.shell_block_reason().await {
                    info!(
                        event_type = "access_control",
                        action = "tcpip_forward",
                        status = "denied",
                        denied_reason = %reason,
                        listen_address = %address,
                        listen_port = %port,
                        "Reverse port forwarding denied"
                    );
                    let _ = reply.send(false);
                } else {
                    self._tcpip_forward(address, port).await?;
                    let _ = reply.send(true);
                }
            }

            ServerHandlerEvent::CancelTcpIpForward(address, port, reply) => {
                self._cancel_tcpip_forward(address, port).await?;
                let _ = reply.send(true);
            }

            ServerHandlerEvent::StreamlocalForward(socket_path, reply) => {
                self._streamlocal_forward(socket_path).await?;
                let _ = reply.send(true);
            }

            ServerHandlerEvent::CancelStreamlocalForward(socket_path, reply) => {
                self._cancel_streamlocal_forward(socket_path).await?;
                let _ = reply.send(true);
            }

            ServerHandlerEvent::AgentForward(channel, reply) => {
                self._agent_forward(channel).await?;
                let _ = reply.send(true);
            }

            ServerHandlerEvent::Disconnect => (),
        }

        Ok(())
    }

    pub async fn handle_session_control(&mut self, command: SessionHandleCommand) -> Result<()> {
        match command {
            SessionHandleCommand::Close => {
                let _ = self.emit_service_message("Session closed by admin").await;
                info!("Session closed by admin");
                self.request_disconnect().await;
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
                        self.service_output.hide_progress().await;
                        self.service_output.emit_output(Bytes::from(format!(
                            "{}{}\r\n",
                            ERASE_PROGRESS_SPINNER,
                            Colour::Black
                                .on(Colour::Green)
                                .paint(" ✓ Warpgate connected ")
                        )));
                    }
                    RCState::Disconnected => {
                        self.service_output.hide_progress().await;
                        self.disconnect_server().await;
                    }
                    _ => {}
                }
            }
            RCEvent::ConnectionError(error) => {
                self.service_output.hide_progress().await;

                match error {
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
                            known_key_type,
                            known_key_base64,
                            received_key_type,
                            received_key_base64
                        );
                        self.emit_service_message(&msg).await?;
                        self.emit_service_message(
                            "If you know that the key is correct (e.g. it has been changed),",
                        )
                        .await?;
                        self.emit_service_message(
                            "you can remove the old key in the Warpgate management UI and try again",
                        )
                        .await?;
                    }
                    ConnectionError::Authentication => {
                        self.service_output.emit_output(Bytes::from(format!(
                            "{}{}\r\n",
                            ERASE_PROGRESS_SPINNER,
                            Colour::Black
                                .on(Colour::Red)
                                .paint(" ✗ SSH target rejected Warpgate authentication request ")
                        )));
                    }
                    error => {
                        self.service_output.emit_output(Bytes::from(format!(
                            "{}{} {}\r\n",
                            ERASE_PROGRESS_SPINNER,
                            Colour::Black.on(Colour::Red).paint(" ✗ Connection failed "),
                            error
                        )));
                    }
                }
            }
            RCEvent::Error(e) => {
                self.service_output.hide_progress().await;
                let _ = self.emit_service_message(&format!("Error: {e}")).await;
                self.disconnect_server().await;
            }
            RCEvent::Output(channel, data) => {
                if let Some(recorder) = self.channel_recorders.get_mut(&channel) {
                    if let Err(error) = recorder
                        .write(TerminalRecordingStreamId::Output, &data)
                        .await
                    {
                        error!(%channel, ?error, "Failed to record terminal data");
                        self.channel_recorders.remove(&channel);
                    }
                }

                if let Some(recorder) = self.traffic_connection_recorders.get_mut(&channel) {
                    if let Err(error) = recorder.write_rx(&data).await {
                        error!(%channel, ?error, "Failed to record traffic data");
                        self.traffic_connection_recorders.remove(&channel);
                    }
                }

                // Handle SFTP responses (server -> client) for file transfer tracking
                if self.sftp_channels.contains(&channel) {
                    self.handle_sftp_response(channel, &data);
                }

                let server_channel_id = self.map_channel_reverse(&channel)?;
                if let Some(session) = self.session_handle.clone() {
                    self.channel_writer.write(
                        session,
                        server_channel_id.0,
                        CryptoVec::from_slice(&data),
                    );
                }
            }
            RCEvent::Success(channel) => {
                let server_channel_id = self.map_channel_reverse(&channel)?;
                self.maybe_with_session(|handle| async move {
                    handle
                        .channel_success(server_channel_id.0)
                        .await
                        .context("failed to send data")
                })
                .await?;
            }
            RCEvent::ChannelFailure(channel) => {
                let server_channel_id = self.map_channel_reverse(&channel)?;
                self.maybe_with_session(|handle| async move {
                    handle
                        .channel_failure(server_channel_id.0)
                        .await
                        .context("failed to send data")
                })
                .await?;
            }
            RCEvent::Close(channel) => {
                // Flush any pending writes before closing the channel
                let _ = self.channel_writer.flush().await;

                let server_channel_id = self.map_channel_reverse(&channel)?;
                let _ = self
                    .maybe_with_session(|handle| async move {
                        handle
                            .close(server_channel_id.0)
                            .await
                            .context("failed to close ch")
                    })
                    .await;
            }
            RCEvent::Eof(channel) => {
                // Flush any pending writes before sending EOF
                let _ = self.channel_writer.flush().await;

                let server_channel_id = self.map_channel_reverse(&channel)?;
                self.maybe_with_session(|handle| async move {
                    handle
                        .eof(server_channel_id.0)
                        .await
                        .context("failed to send eof")
                })
                .await?;
            }
            RCEvent::ExitStatus(channel, code) => {
                // Flush any pending writes before sending exit status
                let _ = self.channel_writer.flush().await;

                let server_channel_id = self.map_channel_reverse(&channel)?;
                self.maybe_with_session(|handle| async move {
                    handle
                        .exit_status_request(server_channel_id.0, code)
                        .await
                        .context("failed to send exit status")
                })
                .await?;
            }
            RCEvent::ExitSignal {
                channel,
                signal_name,
                core_dumped,
                error_message,
                lang_tag,
            } => {
                let server_channel_id = self.map_channel_reverse(&channel)?;
                self.maybe_with_session(|handle| async move {
                    handle
                        .exit_signal_request(
                            server_channel_id.0,
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
                    if let Err(error) = recorder
                        .write(TerminalRecordingStreamId::Error, &data)
                        .await
                    {
                        error!(%channel, ?error, "Failed to record session data");
                        self.channel_recorders.remove(&channel);
                    }
                }
                let server_channel_id = self.map_channel_reverse(&channel)?;
                if let Some(session) = self.session_handle.clone() {
                    self.channel_writer.write_extended(
                        session,
                        server_channel_id.0,
                        ext,
                        CryptoVec::from_slice(&data),
                    );
                }
            }
            RCEvent::HostKeyReceived(key) => {
                self.emit_service_message(&format!(
                    "Host key ({}): {}",
                    key.algorithm(),
                    key.public_key_base64()
                ))
                .await?;
            }
            RCEvent::HostKeyUnknown(key, reply) => {
                self.handle_unknown_host_key(key, reply).await?;
            }
            RCEvent::ForwardedTcpIp(id, params) => {
                if let Some(session) = &mut self.session_handle {
                    let server_channel = session
                        .channel_open_forwarded_tcpip(
                            params.connected_address,
                            params.connected_port,
                            params.originator_address.clone(),
                            params.originator_port,
                        )
                        .await?;

                    self.channel_map
                        .insert(ServerChannelId(server_channel.id()), id);
                    self.all_channels.push(id);

                    let recorder = self
                        .traffic_recorder_for(
                            TrafficRecorderKey::Tcp(
                                params.originator_address.clone(),
                                params.originator_port,
                            ),
                            SshRecordingMetadata::ForwardedTcpIp {
                                host: params.originator_address,
                                port: params.originator_port as u16,
                            },
                        )
                        .await;
                    if let Some(recorder) = recorder {
                        #[allow(clippy::unwrap_used)]
                        let mut recorder = recorder.connection(TrafficConnectionParams::Tcp {
                            dst_addr: Ipv4Addr::from_str("2.2.2.2").unwrap(),
                            dst_port: params.connected_port as u16,
                            src_addr: Ipv4Addr::from_str("1.1.1.1").unwrap(),
                            src_port: params.originator_port as u16,
                        });
                        if let Err(error) = recorder.write_connection_setup().await {
                            error!(channel=%id, ?error, "Failed to record connection setup");
                        }
                        self.traffic_connection_recorders.insert(id, recorder);
                    }
                }
            }
            RCEvent::ForwardedStreamlocal(id, params) => {
                if let Some(session) = &mut self.session_handle {
                    let server_channel = session
                        .channel_open_forwarded_streamlocal(params.socket_path.clone())
                        .await?;

                    self.channel_map
                        .insert(ServerChannelId(server_channel.id()), id);
                    self.all_channels.push(id);

                    let recorder = self
                        .traffic_recorder_for(
                            TrafficRecorderKey::Socket(params.socket_path.clone()),
                            SshRecordingMetadata::ForwardedSocket {
                                path: params.socket_path.clone(),
                            },
                        )
                        .await;
                    if let Some(recorder) = recorder {
                        #[allow(clippy::unwrap_used)]
                        let mut recorder = recorder.connection(TrafficConnectionParams::Socket {
                            socket_path: params.socket_path,
                        });
                        if let Err(error) = recorder.write_connection_setup().await {
                            error!(channel=%id, ?error, "Failed to record connection setup");
                        }
                        self.traffic_connection_recorders.insert(id, recorder);
                    }
                }
            }
            RCEvent::ForwardedAgent(id) => {
                if let Some(session) = &mut self.session_handle {
                    let server_channel = session.channel_open_agent().await?;

                    self.channel_map
                        .insert(ServerChannelId(server_channel.id()), id);
                    self.all_channels.push(id);
                }
            }
            RCEvent::X11(id, originator_address, originator_port) => {
                if let Some(session) = &mut self.session_handle {
                    let server_channel = session
                        .channel_open_x11(originator_address, originator_port)
                        .await?;

                    self.channel_map
                        .insert(ServerChannelId(server_channel.id()), id);
                    self.all_channels.push(id);
                }
            }
        }
        Ok(())
    }

    async fn handle_unknown_host_key(
        &mut self,
        key: PublicKey,
        reply: oneshot::Sender<bool>,
    ) -> Result<()> {
        self.service_output.hide_progress().await;

        let mode = self
            .services
            .config
            .lock()
            .await
            .store
            .ssh
            .host_key_verification;

        if mode == SshHostKeyVerificationMode::AutoAccept {
            let _ = reply.send(true);
            info!("Accepted untrusted host key (auto-accept is enabled)");
            return Ok(());
        }

        if mode == SshHostKeyVerificationMode::AutoReject {
            let _ = reply.send(false);
            info!("Rejected untrusted host key (auto-reject is enabled)");
            return Ok(());
        }

        if self.pty_channels.is_empty() {
            warn!("Target host key is not trusted, but there is no active PTY channel to show the trust prompt on.");
            warn!(
                "Connect to this target with an interactive session once to accept the host key."
            );
            self.request_disconnect().await;
            anyhow::bail!("No PTY channel to show an interactive prompt on")
        }

        self.emit_service_message(&format!(
            "There is no trusted {} key for this host.",
            key.algorithm()
        ))
        .await?;
        self.emit_service_message("Trust this key? (y/n)").await?;

        let mut sub = self
            .hub
            .subscribe(|e| matches!(e, Event::ConsoleInput(_)))
            .await;

        let mut service_output = self.service_output.clone();
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
            service_output.show_progress();
        });

        Ok(())
    }

    async fn maybe_with_session<'a, FN, FT, R>(&'a mut self, f: FN) -> Result<Option<R>>
    where
        FN: FnOnce(&'a mut russh::server::Handle) -> FT + 'a,
        FT: futures::Future<Output = Result<R>>,
    {
        if let Some(handle) = &mut self.session_handle {
            return Ok(Some(f(handle).await?));
        }
        Ok(None)
    }

    async fn _channel_open_direct_tcpip(
        &mut self,
        channel: ServerChannelId,
        params: DirectTCPIPParams,
    ) -> Result<bool> {
        let uuid = Uuid::new_v4();
        self.channel_map.insert(channel, uuid);

        info!(%channel, "Opening direct TCP/IP channel from {}:{} to {}:{}", params.originator_address, params.originator_port, params.host_to_connect, params.port_to_connect);

        let _ = self.maybe_connect_remote().await;

        match self
            .send_command_and_wait(RCCommand::Channel(
                uuid,
                ChannelOperation::OpenDirectTCPIP(params.clone()),
            ))
            .await
        {
            Ok(()) => {
                self.all_channels.push(uuid);

                let recorder = self
                    .traffic_recorder_for(
                        TrafficRecorderKey::Tcp(
                            params.host_to_connect.clone(),
                            params.port_to_connect,
                        ),
                        SshRecordingMetadata::DirectTcpIp {
                            host: params.host_to_connect,
                            port: params.port_to_connect as u16,
                        },
                    )
                    .await;
                if let Some(recorder) = recorder {
                    #[allow(clippy::unwrap_used)]
                    let mut recorder = recorder.connection(TrafficConnectionParams::Tcp {
                        dst_addr: Ipv4Addr::from_str("2.2.2.2").unwrap(),
                        dst_port: params.port_to_connect as u16,
                        src_addr: Ipv4Addr::from_str("1.1.1.1").unwrap(),
                        src_port: params.originator_port as u16,
                    });
                    if let Err(error) = recorder.write_connection_setup().await {
                        error!(%channel, ?error, "Failed to record connection setup");
                    }
                    self.traffic_connection_recorders.insert(uuid, recorder);
                }

                Ok(true)
            }
            Err(SshClientError::Russh(russh::Error::ChannelOpenFailure(_))) => Ok(false),
            Err(x) => Err(x.into()),
        }
    }

    async fn _channel_open_direct_streamlocal(
        &mut self,
        channel: ServerChannelId,
        path: String,
    ) -> Result<bool> {
        let uuid = Uuid::new_v4();
        self.channel_map.insert(channel, uuid);

        info!(%channel, "Opening direct streamlocal channel to {}", path);

        let _ = self.maybe_connect_remote().await;

        match self
            .send_command_and_wait(RCCommand::Channel(
                uuid,
                ChannelOperation::OpenDirectStreamlocal(path.clone()),
            ))
            .await
        {
            Ok(()) => {
                self.all_channels.push(uuid);

                let recorder = self
                    .traffic_recorder_for(
                        TrafficRecorderKey::Socket(path.clone()),
                        SshRecordingMetadata::DirectSocket { path: path.clone() },
                    )
                    .await;
                if let Some(recorder) = recorder {
                    #[allow(clippy::unwrap_used)]
                    let mut recorder =
                        recorder.connection(TrafficConnectionParams::Socket { socket_path: path });
                    if let Err(error) = recorder.write_connection_setup().await {
                        error!(%channel, ?error, "Failed to record connection setup");
                    }
                    self.traffic_connection_recorders.insert(uuid, recorder);
                }

                Ok(true)
            }
            Err(SshClientError::Russh(russh::Error::ChannelOpenFailure(_))) => Ok(false),
            Err(x) => Err(x.into()),
        }
    }

    async fn _window_change_request(
        &mut self,
        server_channel_id: ServerChannelId,
        request: PtyRequest,
    ) -> Result<()> {
        let channel_id = self.map_channel(&server_channel_id)?;
        self.channel_pty_size_map
            .insert(channel_id, request.clone());
        if let Some(recorder) = self.channel_recorders.get_mut(&channel_id) {
            if let Err(error) = recorder
                .write_pty_resize(request.col_width, request.row_height)
                .await
            {
                error!(%channel_id, ?error, "Failed to record terminal data");
                self.channel_recorders.remove(&channel_id);
            }
        }
        self.send_command_and_wait(RCCommand::Channel(
            channel_id,
            ChannelOperation::ResizePty(request),
        ))
        .await?;
        Ok(())
    }

    async fn _channel_exec_request(
        &mut self,
        server_channel_id: ServerChannelId,
        data: Bytes,
    ) -> Result<()> {
        let channel_id = self.map_channel(&server_channel_id)?;

        match std::str::from_utf8(&data) {
            Err(e) => {
                error!(channel=%channel_id, ?data, "Requested exec - invalid UTF-8");
                anyhow::bail!("{e}")
            }
            Ok::<&str, _>(command) => {
                debug!(channel=%channel_id, %command, "Requested exec");

                let _ = self.maybe_connect_remote().await;
                let _ = self.send_command(RCCommand::Channel(
                    channel_id,
                    ChannelOperation::RequestExec(command.to_string()),
                ));
            }
        }

        self.start_terminal_recording(
            channel_id,
            SshRecordingMetadata::Exec {
                // HACK russh ChannelId is opaque except via Display
                channel: server_channel_id.0.to_string().parse().unwrap_or_default(),
            },
        )
        .await;
        Ok(())
    }

    async fn start_terminal_recording(&mut self, channel_id: Uuid, metadata: SshRecordingMetadata) {
        let recorder = async {
            let mut recorder = self
                .services
                .recordings
                .lock()
                .await
                .start::<TerminalRecorder, _>(&self.id, None, metadata)
                .await?;
            if let Some(request) = self.channel_pty_size_map.get(&channel_id) {
                recorder
                    .write_pty_resize(request.col_width, request.row_height)
                    .await?;
            }
            Ok::<_, recordings::Error>(recorder)
        }
        .await;
        match recorder {
            Ok(recorder) => {
                self.channel_recorders.insert(channel_id, recorder);
            }
            Err(error) => match error {
                recordings::Error::Disabled => (),
                error => error!(channel=%channel_id, ?error, "Failed to start recording"),
            },
        }
    }

    async fn _channel_x11_request(
        &mut self,
        server_channel_id: ServerChannelId,
        request: X11Request,
    ) -> Result<()> {
        let channel_id = self.map_channel(&server_channel_id)?;
        debug!(channel=%channel_id, "Requested X11");
        let _ = self.maybe_connect_remote().await;
        self.send_command_and_wait(RCCommand::Channel(
            channel_id,
            ChannelOperation::RequestX11(request),
        ))
        .await?;
        Ok(())
    }

    async fn _channel_env_request(
        &mut self,
        server_channel_id: ServerChannelId,
        name: String,
        value: String,
    ) -> Result<()> {
        let channel_id = self.map_channel(&server_channel_id)?;
        debug!(channel=%channel_id, %name, %value, "Environment");
        self.send_command_and_wait(RCCommand::Channel(
            channel_id,
            ChannelOperation::RequestEnv(name, value),
        ))
        .await?;
        Ok(())
    }

    async fn traffic_recorder_for(
        &mut self,
        key: TrafficRecorderKey,
        metadata: SshRecordingMetadata,
    ) -> Option<&mut TrafficRecorder> {
        if let Vacant(e) = self.traffic_recorders.entry(key.clone()) {
            match self
                .services
                .recordings
                .lock()
                .await
                .start(&self.id, None, metadata)
                .await
            {
                Ok(recorder) => {
                    e.insert(recorder);
                }
                Err(error) => {
                    error!(?key, ?error, "Failed to start recording");
                }
            }
        }
        self.traffic_recorders.get_mut(&key)
    }

    pub async fn _channel_subsystem_request(
        &mut self,
        server_channel_id: ServerChannelId,
        name: String,
    ) -> Result<(), SshClientError> {
        let channel_id = self.map_channel(&server_channel_id)?;
        info!(channel=%channel_id, "Requesting subsystem {}", &name);

        // For SFTP subsystem, always allow the connection but enforce permissions
        // at the operation level. This provides better UX - users see "Permission denied"
        // for specific operations rather than "subsystem request failed".
        if name == "sftp" {
            // Track this channel as SFTP for fine-grained operation blocking
            self.sftp_channels.insert(channel_id);
            // Initialize SFTP channel state for tracking file transfers
            self.sftp_channel_state.insert(
                channel_id,
                SftpChannelState {
                    pending_opens: HashMap::new(),
                    pending_reads: HashMap::new(),
                    tracker: FileTransferTracker::new(self.hash_threshold),
                    client_buf: Vec::new(),
                    pending_forward: Vec::new(),
                    server_buf: Vec::new(),
                    denied_handles: HashSet::new(),
                    pending_cleanup: Vec::new(),
                },
            );
            // Load permissions for later enforcement
            self.load_file_transfer_permission().await;
            let upload_allowed = self
                .file_transfer_permission
                .as_ref()
                .is_some_and(|p| p.upload_allowed);
            let download_allowed = self
                .file_transfer_permission
                .as_ref()
                .is_some_and(|p| p.download_allowed);
            info!(
                channel=%channel_id,
                upload_allowed,
                download_allowed,
                "SFTP subsystem access granted (permissions enforced at operation level)"
            );
        }

        let _ = self.maybe_connect_remote().await;
        self.send_command_and_wait(RCCommand::Channel(
            channel_id,
            ChannelOperation::RequestSubsystem(name),
        ))
        .await?;
        Ok(())
    }

    /// Load file transfer permissions for the current session.
    async fn load_file_transfer_permission(&mut self) {
        let username = match &self.username {
            Some(u) => u.clone(),
            None => {
                warn!("Cannot load file transfer permissions: no authenticated user");
                return;
            }
        };

        let target = match &self.target {
            TargetSelection::Found(t, _) => t.clone(),
            _ => {
                warn!("Cannot load file transfer permissions: no target selected");
                return;
            }
        };

        match self
            .services
            .config_provider
            .lock()
            .await
            .authorize_target_file_transfer(&username, &target)
            .await
        {
            Ok(permission) => {
                debug!(
                    upload=%permission.upload_allowed,
                    download=%permission.download_allowed,
                    "Loaded file transfer permissions"
                );
                self.file_transfer_permission = Some(permission);
            }
            Err(e) => {
                error!(?e, "Failed to load file transfer permissions");
                // Default to no permissions on error
                self.file_transfer_permission = Some(FileTransferPermission::default());
            }
        }
    }

    /// Check if shell/exec access should be blocked based on instance-wide SFTP permission mode.
    /// Returns the reason why shell/exec/forwarding is blocked, or None if allowed.
    ///
    /// Blocked when:
    /// - Role has `file_transfer_only` enabled (SFTP-only access), OR
    /// - Instance `sftp_permission_mode` is "strict" AND the user-target has SFTP restrictions
    async fn shell_block_reason(&mut self) -> Option<String> {
        // Ensure permissions are loaded
        if self.file_transfer_permission.is_none() {
            self.load_file_transfer_permission().await;
        }
        let perm = self.file_transfer_permission.as_ref()?;
        if !perm.shell_blocked {
            return None;
        }
        let target_name = self.get_target_name();
        if perm.file_transfer_only {
            Some(format!(
                "Your role only allows file transfers on target '{target_name}' (file_transfer_only is enabled)"
            ))
        } else {
            Some(format!(
                "Target '{target_name}' restricts file transfers — shell, exec, and forwarding are blocked by security policy"
            ))
        }
    }

    /// Get the current target name for error messages
    fn get_target_name(&self) -> String {
        match &self.target {
            TargetSelection::Found(t, _) => t.name.clone(),
            TargetSelection::NotFound(name) => name.clone(),
            TargetSelection::None => "unknown".to_string(),
        }
    }

    /// Build a detailed permission denied message
    fn build_permission_message(&self, action: &str, path: Option<&str>) -> String {
        let target_name = self.get_target_name();
        match path {
            Some(p) => format!(
                "Permission denied: {action} is not allowed on target '{target_name}' for path '{p}'"
            ),
            None => format!(
                "Permission denied: {action} is not allowed on target '{target_name}'"
            ),
        }
    }

    /// Check SFTP operation against access control policy.
    ///
    /// Uses a reassembly buffer to handle SFTP packets that span multiple SSH
    /// data messages, or multiple SFTP packets concatenated in a single message.
    ///
    /// Data is NOT forwarded to the target until complete SFTP packets are parsed
    /// and verified against the access control policy. This prevents partial
    /// writes from reaching the target before size/permission checks can run.
    ///
    /// Returns:
    ///  - `SftpCheckResult::Pending` if the buffer has an incomplete packet (don't forward yet)
    ///  - `SftpCheckResult::Allowed(bytes)` with the raw bytes to forward to the target
    ///  - `SftpCheckResult::Denied(request_id, message)` if an operation is blocked
    fn check_sftp_operation(&mut self, channel_id: Uuid, data: &[u8]) -> SftpCheckResult {
        // Append incoming data to both the parse buffer and the forward buffer
        if let Some(state) = self.sftp_channel_state.get_mut(&channel_id) {
            state.client_buf.extend_from_slice(data);
            state.pending_forward.extend_from_slice(data);
        } else {
            // Not an SFTP channel state — shouldn't happen, but forward data as-is
            return SftpCheckResult::Allowed(data.to_vec());
        }

        // Parse all complete packets from the buffer
        let (packets, consumed) = if let Some(state) = self.sftp_channel_state.get_mut(&channel_id) {
            let before_len = state.client_buf.len();
            let pkts = crate::sftp::parse_all_packets(&mut state.client_buf);
            let consumed = before_len - state.client_buf.len();
            (pkts, consumed)
        } else {
            return SftpCheckResult::Allowed(data.to_vec());
        };

        if packets.is_empty() {
            // No complete packets yet — buffer is accumulating, hold data
            return SftpCheckResult::Pending;
        }

        // Drain the consumed raw bytes from pending_forward for forwarding
        let forward_bytes = if let Some(state) = self.sftp_channel_state.get_mut(&channel_id) {
            state.pending_forward.drain(..consumed).collect::<Vec<u8>>()
        } else {
            return SftpCheckResult::Allowed(data.to_vec());
        };

        // Check permissions — if none configured, allow everything
        let permission = match self.file_transfer_permission.clone() {
            Some(p) => p,
            None => return SftpCheckResult::Allowed(forward_bytes),
        };

        // Process each parsed packet, return denial for the first blocked one
        for packet in &packets {
            let Some(operation) = packet_to_operation(packet) else {
                continue; // Read-only metadata packet, safe to forward
            };
            if let Some((request_id, msg)) = self.check_sftp_operation_inner(channel_id, &operation, &permission) {
                // Clear both buffers on denial to avoid stale data
                if let Some(state) = self.sftp_channel_state.get_mut(&channel_id) {
                    state.client_buf.clear();
                    state.pending_forward.clear();
                }
                return SftpCheckResult::Denied(request_id, msg);
            }
        }

        // All packets allowed — forward the consumed bytes to the target
        SftpCheckResult::Allowed(forward_bytes)
    }

    /// Inner check for a single parsed SFTP operation.
    /// Returns Some((request_id, message)) if blocked, None if allowed.
    fn check_sftp_operation_inner(
        &mut self,
        channel_id: Uuid,
        operation: &SftpFileOperation,
        permission: &FileTransferPermission,
    ) -> Option<(u32, String)> {

        match operation {
            SftpFileOperation::Open {
                request_id,
                ref path,
                is_upload,
                is_download,
                ..
            } => {
                // Determine transfer direction
                let direction = if *is_upload {
                    TransferDirection::Upload
                } else {
                    TransferDirection::Download
                };

                // Check basic upload/download permission
                if *is_upload && !permission.upload_allowed {
                    let msg = self.build_permission_message("file upload", Some(path.as_str()));
                    self.log_transfer_denied(
                        "sftp",
                        direction,
                        Some(path.as_str()),
                        "upload not permitted",
                    );
                    return Some((*request_id, msg));
                }
                if *is_download && !permission.download_allowed {
                    let msg = self.build_permission_message("file download", Some(path.as_str()));
                    self.log_transfer_denied(
                        "sftp",
                        direction,
                        Some(path.as_str()),
                        "download not permitted",
                    );
                    return Some((*request_id, msg));
                }

                // Check advanced restrictions (path, extension)
                if let Err(reason) = self.check_advanced_restrictions(path.as_str(), None) {
                    let msg = self.build_permission_message(&reason, Some(path.as_str()));
                    self.log_transfer_denied("sftp", direction, Some(path.as_str()), &reason);
                    return Some((*request_id, msg));
                }

                // Track pending open - we'll complete it when we receive the HANDLE response
                if let Some(state) = self.sftp_channel_state.get_mut(&channel_id) {
                    state.pending_opens.insert(
                        *request_id,
                        PendingOpen {
                            path: path.clone(),
                            direction,
                        },
                    );
                }

                self.log_transfer_started("sftp", direction, path.as_str());
            }
            SftpFileOperation::Write {
                request_id,
                ref handle,
                ref data,
                ..
            } => {
                // If this handle was already denied, silently reject without logging
                if let Some(state) = self.sftp_channel_state.get(&channel_id) {
                    if state.denied_handles.contains(handle) {
                        let msg = self.build_permission_message("file size limit exceeded", None);
                        return Some((*request_id, msg));
                    }
                }

                if !permission.upload_allowed {
                    let msg = self.build_permission_message("file write", None);
                    self.log_transfer_denied(
                        "sftp",
                        TransferDirection::Upload,
                        None,
                        "upload not permitted",
                    );
                    return Some((*request_id, msg));
                }

                // Check max_file_size: cumulative bytes + this write
                if let Some(max_size) = permission.max_file_size {
                    if let Some(state) = self.sftp_channel_state.get(&channel_id) {
                        if let Some((_path, _dir, current_bytes)) =
                            state.tracker.get_transfer(handle)
                        {
                            let new_total = current_bytes + data.len() as u64;
                            if new_total > max_size as u64 {
                                let path_str = _path.to_string();
                                let handle_str = String::from_utf8_lossy(handle).to_string();
                                let reason = format!(
                                    "file size {new_total} exceeds limit {max_size}"
                                );
                                let msg = self.build_permission_message(
                                    &reason,
                                    Some(&path_str),
                                );
                                self.log_transfer_denied(
                                    "sftp",
                                    TransferDirection::Upload,
                                    Some(&path_str),
                                    &reason,
                                );
                                // Mark handle as denied + queue server-side cleanup
                                if let Some(state) = self.sftp_channel_state.get_mut(&channel_id) {
                                    state.denied_handles.insert(handle.clone());
                                    state.pending_cleanup.push((path_str, handle_str));
                                }
                                return Some((*request_id, msg));
                            }
                        }
                    }
                }

                // Track data for hash calculation (upload: client -> server)
                // Data is now directly available in the operation struct
                if let Some(state) = self.sftp_channel_state.get_mut(&channel_id) {
                    state.tracker.data_transferred(handle, data);
                }
            }
            SftpFileOperation::Read {
                request_id,
                ref handle,
                ..
            } => {
                if !permission.download_allowed {
                    let msg = self.build_permission_message("file read", None);
                    self.log_transfer_denied(
                        "sftp",
                        TransferDirection::Download,
                        None,
                        "download not permitted",
                    );
                    return Some((*request_id, msg));
                }
                // Track this READ request so we can associate the DATA response with the handle
                if let Some(state) = self.sftp_channel_state.get_mut(&channel_id) {
                    state.pending_reads.insert(*request_id, handle.clone());
                }
            }
            SftpFileOperation::Remove {
                request_id,
                ref path,
            } => {
                if !permission.upload_allowed {
                    let msg = self.build_permission_message("file remove", Some(path));
                    self.log_transfer_denied(
                        "sftp",
                        TransferDirection::Upload,
                        Some(path),
                        "remove not permitted",
                    );
                    return Some((*request_id, msg));
                }
                if let Err(reason) = self.check_advanced_restrictions(path, None) {
                    let msg = self.build_permission_message(&reason, Some(path));
                    self.log_transfer_denied(
                        "sftp",
                        TransferDirection::Upload,
                        Some(path),
                        &reason,
                    );
                    return Some((*request_id, msg));
                }
            }
            SftpFileOperation::Rename {
                request_id,
                ref old_path,
                ref new_path,
                ..
            } => {
                if !permission.upload_allowed {
                    let msg = self.build_permission_message("file rename", Some(old_path));
                    self.log_transfer_denied(
                        "sftp",
                        TransferDirection::Upload,
                        Some(old_path),
                        "rename not permitted",
                    );
                    return Some((*request_id, msg));
                }
                // Check both paths
                if let Err(reason) = self.check_advanced_restrictions(old_path, None) {
                    let msg = self.build_permission_message(&reason, Some(old_path));
                    self.log_transfer_denied(
                        "sftp",
                        TransferDirection::Upload,
                        Some(old_path),
                        &reason,
                    );
                    return Some((*request_id, msg));
                }
                if let Err(reason) = self.check_advanced_restrictions(new_path, None) {
                    let msg = self.build_permission_message(&reason, Some(new_path));
                    self.log_transfer_denied(
                        "sftp",
                        TransferDirection::Upload,
                        Some(new_path),
                        &reason,
                    );
                    return Some((*request_id, msg));
                }
            }
            SftpFileOperation::Mkdir {
                request_id,
                ref path,
            } => {
                if !permission.upload_allowed {
                    let msg = self.build_permission_message("mkdir", Some(path));
                    self.log_transfer_denied(
                        "sftp",
                        TransferDirection::Upload,
                        Some(path),
                        "mkdir not permitted",
                    );
                    return Some((*request_id, msg));
                }
                if let Err(reason) = self.check_advanced_restrictions(path, None) {
                    let msg = self.build_permission_message(&reason, Some(path));
                    self.log_transfer_denied(
                        "sftp",
                        TransferDirection::Upload,
                        Some(path),
                        &reason,
                    );
                    return Some((*request_id, msg));
                }
            }
            SftpFileOperation::Rmdir {
                request_id,
                ref path,
            } => {
                if !permission.upload_allowed {
                    let msg = self.build_permission_message("rmdir", Some(path));
                    self.log_transfer_denied(
                        "sftp",
                        TransferDirection::Upload,
                        Some(path),
                        "rmdir not permitted",
                    );
                    return Some((*request_id, msg));
                }
                if let Err(reason) = self.check_advanced_restrictions(path, None) {
                    let msg = self.build_permission_message(&reason, Some(path));
                    self.log_transfer_denied(
                        "sftp",
                        TransferDirection::Upload,
                        Some(path),
                        &reason,
                    );
                    return Some((*request_id, msg));
                }
            }
            SftpFileOperation::Setstat {
                request_id,
                ref path,
            } => {
                if !permission.upload_allowed {
                    let msg = self.build_permission_message("setstat", Some(path));
                    self.log_transfer_denied(
                        "sftp",
                        TransferDirection::Upload,
                        Some(path),
                        "setstat not permitted",
                    );
                    return Some((*request_id, msg));
                }
                if let Err(reason) = self.check_advanced_restrictions(path, None) {
                    let msg = self.build_permission_message(&reason, Some(path));
                    self.log_transfer_denied(
                        "sftp",
                        TransferDirection::Upload,
                        Some(path),
                        &reason,
                    );
                    return Some((*request_id, msg));
                }
            }
            SftpFileOperation::Symlink {
                request_id,
                ref link_path,
                ref target_path,
                ..
            } => {
                if !permission.upload_allowed {
                    let msg = self.build_permission_message("symlink", Some(link_path));
                    self.log_transfer_denied(
                        "sftp",
                        TransferDirection::Upload,
                        Some(link_path),
                        "symlink not permitted",
                    );
                    return Some((*request_id, msg));
                }
                if let Err(reason) = self.check_advanced_restrictions(link_path, None) {
                    let msg = self.build_permission_message(&reason, Some(link_path));
                    self.log_transfer_denied(
                        "sftp",
                        TransferDirection::Upload,
                        Some(link_path),
                        &reason,
                    );
                    return Some((*request_id, msg));
                }
                if let Err(reason) = self.check_advanced_restrictions(target_path, None) {
                    let msg = self.build_permission_message(&reason, Some(target_path));
                    self.log_transfer_denied(
                        "sftp",
                        TransferDirection::Upload,
                        Some(target_path),
                        &reason,
                    );
                    return Some((*request_id, msg));
                }
            }
            SftpFileOperation::Extended {
                request_id,
                ref request_name,
            } => {
                // Allowlist of known-safe read-only extensions
                const SAFE_EXTENSIONS: &[&str] = &[
                    "statvfs@openssh.com",  // Filesystem stats (read-only)
                    "fstatvfs@openssh.com", // Filesystem stats by handle (read-only)
                    "fsync@openssh.com",    // Flush file data (safe, no data transfer)
                    "limits@openssh.com",   // Query server limits (read-only, required by OpenSSH 9.x+ clients)
                ];

                if SAFE_EXTENSIONS.contains(&request_name.as_str()) {
                    // Safe extension — allow through
                    return None;
                }

                // Extensions that modify files — check upload permission
                const WRITE_EXTENSIONS: &[&str] = &[
                    "posix-rename@openssh.com", // Atomic rename
                    "hardlink@openssh.com",     // Create hard link
                    "lsetstat@openssh.com",     // Set attributes without following symlinks
                ];

                if WRITE_EXTENSIONS.contains(&request_name.as_str()) {
                    if !permission.upload_allowed {
                        self.log_transfer_denied(
                            "sftp-extended",
                            TransferDirection::Upload,
                            Some(request_name),
                            "upload not permitted",
                        );
                        return Some((
                            *request_id,
                            format!(
                                "SFTP extended operation '{}' denied: upload not permitted",
                                request_name
                            ),
                        ));
                    }
                    // Allowed — upload permitted
                    return None;
                }

                // Unknown extension — block if any SFTP restrictions are active
                if !permission.upload_allowed || !permission.download_allowed {
                    warn!(%request_name, "Blocking unknown SFTP extension (restrictions active)");
                    return Some((
                        *request_id,
                        format!("SFTP extended operation '{}' not permitted", request_name),
                    ));
                }

                // No restrictions active — allow unknown extensions through
            }
            SftpFileOperation::Close { ref handle, .. } => {
                // Handle file close - finalize transfer and log completion
                if let Some(state) = self.sftp_channel_state.get_mut(&channel_id) {
                    if let Some(complete) = state.tracker.file_closed(handle) {
                        self.log_transfer_completed(&complete, "sftp");
                    }
                }
            }
        }

        None // Operation allowed
    }

    /// Handle SFTP response from server (for tracking file handles and download data).
    ///
    /// Uses a reassembly buffer to handle SFTP packets that span multiple SSH
    /// data messages, or multiple SFTP packets concatenated in a single message.
    fn handle_sftp_response(&mut self, channel_id: Uuid, data: &[u8]) {
        // Append incoming data to the server reassembly buffer
        if let Some(state) = self.sftp_channel_state.get_mut(&channel_id) {
            state.server_buf.extend_from_slice(data);
        } else {
            return;
        }

        // Parse all complete packets from the buffer
        let packets = if let Some(state) = self.sftp_channel_state.get_mut(&channel_id) {
            crate::sftp::parse_all_packets(&mut state.server_buf)
        } else {
            return;
        };

        // Process each parsed response packet
        for packet in &packets {
            let Some(response) = packet_to_response(packet) else {
                continue;
            };

            match response {
                SftpResponse::Handle { request_id, handle } => {
                    // Got a file handle - associate it with the pending open
                    if let Some(state) = self.sftp_channel_state.get_mut(&channel_id) {
                        if let Some(pending) = state.pending_opens.remove(&request_id) {
                            state
                                .tracker
                                .file_opened(handle, pending.path, pending.direction);
                        }
                    }
                }
                SftpResponse::Data {
                    request_id,
                    data: file_data,
                } => {
                    // Download data from server - track for hash calculation
                    // Look up which handle this data belongs to via the pending_reads mapping
                    if let Some(state) = self.sftp_channel_state.get_mut(&channel_id) {
                        if let Some(handle) = state.pending_reads.remove(&request_id) {
                            // Track download data for this handle
                            state.tracker.data_transferred(&handle, &file_data);
                        }
                    }
                }
                SftpResponse::Status { .. } => {
                    // Status response - could indicate success/failure of operations
                    // Not needed for basic tracking
                }
            }
        }
    }

    /// Send Close + Remove to the server to delete partial files after a size-limit denial.
    fn cleanup_denied_transfers(&mut self, channel_id: Uuid) {
        let cleanups = if let Some(state) = self.sftp_channel_state.get_mut(&channel_id) {
            std::mem::take(&mut state.pending_cleanup)
        } else {
            return;
        };

        // Use a synthetic request_id range that won't collide with client IDs
        let mut cleanup_id: u32 = 0xFFFF_0000;
        for (path, handle_str) in cleanups {
            // Close the file handle on the server
            let close_pkt = build_close_packet(cleanup_id, &handle_str);
            if !close_pkt.is_empty() {
                let _ = self.send_command(RCCommand::Channel(
                    channel_id,
                    ChannelOperation::Data(Bytes::from(close_pkt)),
                ));
            }
            cleanup_id = cleanup_id.wrapping_add(1);

            // Remove the partial file on the server
            let remove_pkt = build_remove_packet(cleanup_id, &path);
            if !remove_pkt.is_empty() {
                let _ = self.send_command(RCCommand::Channel(
                    channel_id,
                    ChannelOperation::Data(Bytes::from(remove_pkt)),
                ));
                info!(
                    event_type = "file_transfer",
                    remote_path = %path,
                    "Removed partial file from target after size limit denial"
                );
            }
            cleanup_id = cleanup_id.wrapping_add(1);
        }
    }

    /// Send SFTP permission denied response to client
    async fn send_sftp_permission_denied(
        &mut self,
        server_channel_id: ServerChannelId,
        request_id: u32,
        message: &str,
    ) -> Result<()> {
        let response = build_denial_response(request_id, message);

        if let Some(session) = self.session_handle.clone() {
            self.channel_writer.write(
                session,
                server_channel_id.0,
                CryptoVec::from_slice(&response),
            );
        }

        Ok(())
    }

    /// Log file transfer started event
    fn log_transfer_started(&self, protocol: &str, direction: TransferDirection, path: &str) {
        info!(
            event_type = "file_transfer",
            protocol = protocol,
            direction = %direction,
            status = "started",
            remote_path = path,
            "File transfer started"
        );
    }

    /// Log file transfer completed event
    fn log_transfer_completed(&self, info: &TransferComplete, protocol: &str) {
        info!(
            event_type = "file_transfer",
            protocol = protocol,
            direction = %info.direction,
            status = "completed",
            remote_path = %info.path,
            file_size = info.bytes_transferred,
            bytes_transferred = info.bytes_transferred,
            file_hash = info.hash.as_deref().unwrap_or(""),
            hash_algorithm = "sha256",
            duration_ms = info.duration_ms,
            "File transfer completed"
        );
    }

    /// Log file transfer denied event
    fn log_transfer_denied(
        &self,
        protocol: &str,
        direction: TransferDirection,
        path: Option<&str>,
        reason: &str,
    ) {
        tracing::info!(
            event_type = "file_transfer",
            protocol = protocol,
            direction = %direction,
            remote_path = path,
            status = "denied",
            denied_reason = reason,
            "File transfer denied"
        );
    }

    /// Check if a path is allowed based on path restrictions
    fn is_path_allowed(&self, path: &str, allowed_paths: &[String]) -> bool {
        if allowed_paths.is_empty() {
            return true;
        }
        for pattern in allowed_paths {
            // Simple glob matching: support * as wildcard
            if pattern.ends_with("/*") {
                let prefix = &pattern[..pattern.len() - 2];
                if path.starts_with(prefix) {
                    return true;
                }
            } else if pattern.ends_with("/**") {
                let prefix = &pattern[..pattern.len() - 3];
                if path.starts_with(prefix) {
                    return true;
                }
            } else if pattern == path {
                return true;
            }
        }
        false
    }

    /// Check if a file extension is blocked
    fn is_extension_blocked(&self, path: &str, blocked_extensions: &[String]) -> bool {
        if blocked_extensions.is_empty() {
            return false;
        }
        for ext in blocked_extensions {
            let ext_lower = ext.to_lowercase();
            let ext_with_dot = if ext_lower.starts_with('.') {
                ext_lower
            } else {
                format!(".{ext_lower}")
            };
            if path.to_lowercase().ends_with(&ext_with_dot) {
                return true;
            }
        }
        false
    }

    /// Check advanced restrictions (path, extension, size) for a file operation
    fn check_advanced_restrictions(
        &self,
        path: &str,
        file_size: Option<u64>,
    ) -> Result<(), String> {
        let Some(ref permission) = self.file_transfer_permission else {
            return Ok(());
        };

        // Check path restrictions
        if let Some(ref allowed_paths) = permission.allowed_paths {
            if !self.is_path_allowed(path, allowed_paths) {
                return Err(format!("path '{path}' not in allowed paths"));
            }
        }

        // Check extension restrictions
        if let Some(ref blocked_extensions) = permission.blocked_extensions {
            if self.is_extension_blocked(path, blocked_extensions) {
                return Err(format!("file extension blocked for '{path}'"));
            }
        }

        // Check size limit
        if let (Some(max_size), Some(size)) = (permission.max_file_size, file_size) {
            if size > max_size as u64 {
                return Err(format!("file size {size} exceeds limit {max_size}"));
            }
        }

        Ok(())
    }

    async fn _data(&mut self, server_channel_id: ServerChannelId, data: Bytes) -> Result<()> {
        let channel_id = self.map_channel(&server_channel_id)?;
        debug!(channel=%server_channel_id.0, ?data, "Data");
        if self.rc_state == RCState::Connecting && data.first() == Some(&3) {
            info!(channel=%channel_id, "User requested connection abort (Ctrl-C)");
            self.request_disconnect().await;
            return Ok(());
        }

        // Check if this is an SFTP channel and inspect packets for access control
        if self.sftp_channels.contains(&channel_id) {
            match self.check_sftp_operation(channel_id, &data) {
                SftpCheckResult::Pending => {
                    // Incomplete SFTP packet — hold data, don't forward yet
                    return Ok(());
                }
                SftpCheckResult::Denied(request_id, message) => {
                    // Send permission denied response to client
                    self.send_sftp_permission_denied(server_channel_id, request_id, &message)
                        .await?;
                    // Clean up partial files on the server (Close handle + Remove file)
                    self.cleanup_denied_transfers(channel_id);
                    return Ok(()); // Don't forward to target
                }
                SftpCheckResult::Allowed(forward_data) => {
                    // Forward the verified SFTP data to the target
                    let forward = Bytes::from(forward_data);
                    if !forward.is_empty() {
                        let _ = self.send_command(RCCommand::Channel(
                            channel_id,
                            ChannelOperation::Data(forward),
                        ));
                    }
                    return Ok(());
                }
            }
        }

        if let Some(recorder) = self.channel_recorders.get_mut(&channel_id) {
            if let Err(error) = recorder
                .write(TerminalRecordingStreamId::Input, &data)
                .await
            {
                error!(channel=%channel_id, ?error, "Failed to record terminal data");
                self.channel_recorders.remove(&channel_id);
            }
        }

        if let Some(recorder) = self.traffic_connection_recorders.get_mut(&channel_id) {
            if let Err(error) = recorder.write_tx(&data).await {
                error!(channel=%channel_id, ?error, "Failed to record traffic data");
                self.traffic_connection_recorders.remove(&channel_id);
            }
        }

        if self.pty_channels.contains(&channel_id) {
            let _ = self
                .event_sender
                .send_once(Event::ConsoleInput(data.clone()))
                .await;
        }

        let _ = self.send_command(RCCommand::Channel(channel_id, ChannelOperation::Data(data)));
        Ok(())
    }

    async fn _extended_data(
        &mut self,
        server_channel_id: ServerChannelId,
        code: u32,
        data: Bytes,
    ) -> Result<()> {
        let channel_id = self.map_channel(&server_channel_id)?;
        debug!(channel=%server_channel_id.0, ?data, "Data");
        let _ = self.send_command(RCCommand::Channel(
            channel_id,
            ChannelOperation::ExtendedData { ext: code, data },
        ));
        Ok(())
    }

    async fn _tcpip_forward(&mut self, address: String, port: u32) -> Result<()> {
        info!(%address, %port, "Remote port forwarding requested");
        let _ = self.maybe_connect_remote().await;
        self.send_command_and_wait(RCCommand::ForwardTCPIP(address, port))
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn _cancel_tcpip_forward(&mut self, address: String, port: u32) -> Result<()> {
        info!(%address, %port, "Remote port forwarding cancelled");
        self.send_command_and_wait(RCCommand::CancelTCPIPForward(address, port))
            .await
            .map_err(anyhow::Error::from)
    }

    async fn _streamlocal_forward(&mut self, socket_path: String) -> Result<()> {
        info!(%socket_path, "Remote UNIX socket forwarding requested");
        let _ = self.maybe_connect_remote().await;
        self.send_command_and_wait(RCCommand::StreamlocalForward(socket_path))
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn _cancel_streamlocal_forward(&mut self, socket_path: String) -> Result<()> {
        info!(%socket_path, "Remote UNIX socket forwarding cancelled");
        self.send_command_and_wait(RCCommand::CancelStreamlocalForward(socket_path))
            .await
            .map_err(anyhow::Error::from)
    }

    async fn _agent_forward(&mut self, server_channel_id: ServerChannelId) -> Result<()> {
        let channel_id = self.map_channel(&server_channel_id)?;
        debug!(channel=%channel_id, "Requested Agent Forwarding");
        self.send_command_and_wait(RCCommand::Channel(
            channel_id,
            ChannelOperation::AgentForward,
        ))
        .await?;
        Ok(())
    }

    async fn _auth_publickey_offer(
        &mut self,
        ssh_username: Secret<String>,
        key: PublicKey,
    ) -> russh::server::Auth {
        let selector: AuthSelector = ssh_username.expose_secret().into();

        info!(
            "Client offers public key auth as {selector:?} with key {}",
            key.public_key_base64()
        );

        if !self.allowed_auth_methods.contains(&MethodKind::PublicKey) {
            warn!("Client attempted public key auth even though it was not advertised");
            return russh::server::Auth::reject();
        }

        if let Ok(true) = self
            .try_validate_public_key_offer(
                &selector,
                Some(AuthCredential::PublicKey {
                    kind: key.algorithm(),
                    public_key_bytes: Bytes::from(key.public_key_bytes()),
                }),
            )
            .await
        {
            return russh::server::Auth::Accept;
        }

        let selector: AuthSelector = ssh_username.expose_secret().into();
        match self.try_auth_lazy(&selector, None).await {
            Ok(AuthResult::Need(kinds)) => russh::server::Auth::Reject {
                proceed_with_methods: Some(self.get_remaining_auth_methods(kinds)),
                partial_success: false,
            },
            _ => russh::server::Auth::reject(),
        }
    }

    async fn _auth_publickey(
        &mut self,
        ssh_username: Secret<String>,
        key: PublicKey,
    ) -> russh::server::Auth {
        let selector: AuthSelector = ssh_username.expose_secret().into();

        info!(
            "Public key auth as {selector:?} with key {}",
            key.public_key_base64()
        );

        if !self.allowed_auth_methods.contains(&MethodKind::PublicKey) {
            warn!("Client attempted public key auth even though it was not advertised");
            return russh::server::Auth::reject();
        }

        let key = Some(AuthCredential::PublicKey {
            kind: key.algorithm(),
            public_key_bytes: Bytes::from(key.public_key_bytes()),
        });

        let result = self.try_auth_lazy(&selector, key.clone()).await;

        match result {
            Ok(AuthResult::Accepted { .. }) => {
                // Update last_used timestamp
                if let Err(err) = self
                    .services
                    .config_provider
                    .lock()
                    .await
                    .update_public_key_last_used(key.clone())
                    .await
                {
                    warn!(?err, "Failed to update last_used for public key");
                }
                russh::server::Auth::Accept
            }
            Ok(AuthResult::Rejected) => russh::server::Auth::Reject {
                proceed_with_methods: Some(MethodSet::all()),
                partial_success: false,
            },
            Ok(AuthResult::Need(kinds)) => russh::server::Auth::Reject {
                proceed_with_methods: Some(self.get_remaining_auth_methods(kinds)),
                partial_success: false,
            },
            Err(error) => {
                error!(?error, "Failed to verify credentials");
                russh::server::Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                }
            }
        }
    }

    async fn _auth_password(
        &mut self,
        ssh_username: Secret<String>,
        password: Secret<String>,
    ) -> russh::server::Auth {
        let selector: AuthSelector = ssh_username.expose_secret().into();
        info!("Password auth as {selector:?}");

        if !self.allowed_auth_methods.contains(&MethodKind::Password) {
            warn!("Client attempted password auth even though it was not advertised");
            return russh::server::Auth::reject();
        }

        match self
            .try_auth_lazy(&selector, Some(AuthCredential::Password(password)))
            .await
        {
            Ok(AuthResult::Accepted { .. }) => russh::server::Auth::Accept,
            Ok(AuthResult::Rejected) => russh::server::Auth::reject(),
            Ok(AuthResult::Need(kinds)) => russh::server::Auth::Reject {
                proceed_with_methods: Some(self.get_remaining_auth_methods(kinds)),
                partial_success: false,
            },
            Err(error) => {
                error!(?error, "Failed to verify credentials");
                russh::server::Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                }
            }
        }
    }

    async fn _auth_keyboard_interactive(
        &mut self,
        ssh_username: Secret<String>,
        response: Option<Secret<String>>,
    ) -> russh::server::Auth {
        let selector: AuthSelector = ssh_username.expose_secret().into();
        info!("Keyboard-interactive auth as {:?}", selector);

        if !self
            .allowed_auth_methods
            .contains(&MethodKind::KeyboardInteractive)
        {
            warn!("Client attempted keyboard-interactive auth even though it was not advertised");
            return russh::server::Auth::reject();
        }

        let cred;
        match &mut self.keyboard_interactive_state {
            KeyboardInteractiveState::None => {
                cred = None;
            }
            KeyboardInteractiveState::OtpRequested => {
                cred = response.map(AuthCredential::Otp);
            }
            KeyboardInteractiveState::WebAuthRequested(event) => {
                cred = None;
                let _ = event.recv().await;
                // the auth state has been updated by now
            }
        }

        self.keyboard_interactive_state = KeyboardInteractiveState::None;

        match self.try_auth_lazy(&selector, cred).await {
            Ok(AuthResult::Accepted { .. }) => russh::server::Auth::Accept,
            Ok(AuthResult::Rejected) => russh::server::Auth::reject(),
            Ok(AuthResult::Need(kinds)) => {
                if kinds.contains(&CredentialKind::Totp) {
                    self.keyboard_interactive_state = KeyboardInteractiveState::OtpRequested;
                    russh::server::Auth::Partial {
                        name: Cow::Borrowed("Two-factor authentication"),
                        instructions: Cow::Borrowed(""),
                        prompts: Cow::Owned(vec![(Cow::Borrowed("One-time password: "), true)]),
                    }
                } else if kinds.contains(&CredentialKind::WebUserApproval) {
                    let Some(auth_state) = self.auth_state.as_ref() else {
                        return russh::server::Auth::Reject {
                            proceed_with_methods: None,
                            partial_success: false,
                        };
                    };
                    let identification_string =
                        auth_state.lock().await.identification_string().to_owned();
                    let auth_state_id = *auth_state.lock().await.id();
                    let event = self
                        .services
                        .auth_state_store
                        .lock()
                        .await
                        .subscribe(auth_state_id);
                    self.keyboard_interactive_state =
                        KeyboardInteractiveState::WebAuthRequested(event);

                    let login_url = match auth_state
                        .lock()
                        .await
                        .construct_web_approval_url(&*self.services.config.lock().await)
                    {
                        Ok(login_url) => login_url,
                        Err(error) => {
                            error!(?error, "Failed to construct external URL");
                            return russh::server::Auth::Reject {
                                proceed_with_methods: None,
                                partial_success: false,
                            };
                        }
                    };

                    russh::server::Auth::Partial {
                        name: Cow::Borrowed("Warpgate authentication"),
                        instructions: Cow::Owned(format!(
                            concat!(
                            "-----------------------------------------------------------------------\n",
                            "Warpgate authentication: please open the following URL in your browser:\n",
                            "{}\n\n",
                            "Make sure you're seeing this security key: {}\n",
                            "-----------------------------------------------------------------------\n"
                        ),
                            login_url,
                            identification_string
                                .chars()
                                .map(|x| x.to_string())
                                .collect::<Vec<_>>()
                                .join(" ")
                        )),
                        prompts: Cow::Owned(vec![(Cow::Borrowed("Press Enter when done: "), true)]),
                    }
                } else {
                    russh::server::Auth::Reject {
                        proceed_with_methods: None,
                        partial_success: false,
                    }
                }
            }
            Err(error) => {
                error!(?error, "Failed to verify credentials");
                russh::server::Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                }
            }
        }
    }

    fn get_remaining_auth_methods(&self, kinds: HashSet<CredentialKind>) -> MethodSet {
        let mut m = MethodSet::empty();

        for cred_kind in kinds {
            let method_kind = match cred_kind {
                CredentialKind::Password => MethodKind::Password,
                CredentialKind::Totp => MethodKind::KeyboardInteractive,
                CredentialKind::WebUserApproval => MethodKind::KeyboardInteractive,
                CredentialKind::PublicKey => MethodKind::PublicKey,
                CredentialKind::Sso => MethodKind::KeyboardInteractive,
                CredentialKind::Certificate => {
                    // Certificate authentication is not supported for SSH protocol
                    // This credential type is primarily for Kubernetes
                    continue;
                }
            };
            if self.allowed_auth_methods.contains(&method_kind) {
                m.push(method_kind);
            }
        }

        if m.contains(&MethodKind::KeyboardInteractive) {
            // Ensure keyboard-interactive is always the last method
            m.push(MethodKind::KeyboardInteractive);
        }

        m
    }

    async fn try_validate_public_key_offer(
        &mut self,
        selector: &AuthSelector,
        credential: Option<AuthCredential>,
    ) -> Result<bool> {
        match selector {
            AuthSelector::User { username, .. } => {
                let cp = self.services.config_provider.clone();

                if let Some(credential) = credential {
                    return Ok(cp
                        .lock()
                        .await
                        .validate_credential(username, &credential)
                        .await?);
                }

                Ok(false)
            }
            _ => Ok(false),
        }
    }

    /// As try_auth_lazy is called multiple times, this memoization prevents
    /// consuming the ticket multiple times, depleting its uses.
    async fn try_auth_lazy(
        &mut self,
        selector: &AuthSelector,
        credential: Option<AuthCredential>,
    ) -> Result<AuthResult> {
        if let AuthSelector::Ticket { secret } = selector {
            if let Some(ref csta) = self.cached_successful_ticket_auth {
                // Only if the client hasn't maliciously changed the username
                // between auth attempts
                if &csta.ticket == secret {
                    return Ok(AuthResult::Accepted {
                        user_info: csta.user_info.clone(),
                    });
                }
            }

            let result = self.try_auth_eager(selector, credential).await?;
            if let AuthResult::Accepted { ref user_info } = result {
                self.cached_successful_ticket_auth = Some(CachedSuccessfulTicketAuth {
                    ticket: secret.clone(),
                    user_info: user_info.clone(),
                });
            }

            return Ok(result);
        }
        self.try_auth_eager(selector, credential).await
    }

    async fn try_auth_eager(
        &mut self,
        selector: &AuthSelector,
        credential: Option<AuthCredential>,
    ) -> Result<AuthResult> {
        match selector {
            AuthSelector::User {
                username,
                target_name,
            } => {
                let cp = self.services.config_provider.clone();

                let state_arc = self.get_auth_state(username).await?;
                let mut state = state_arc.lock().await;

                if let Some(credential) = credential {
                    if cp
                        .lock()
                        .await
                        .validate_credential(username, &credential)
                        .await?
                    {
                        state.add_valid_credential(credential);
                    }
                }

                let user_auth_result = state.verify();

                match user_auth_result {
                    AuthResult::Accepted { user_info } => {
                        self.services
                            .auth_state_store
                            .lock()
                            .await
                            .complete(state.id())
                            .await;
                        let target_auth_result = {
                            self.services
                                .config_provider
                                .lock()
                                .await
                                .authorize_target(&user_info.username, target_name)
                                .await?
                        };
                        if !target_auth_result {
                            warn!(
                                "Target {} not authorized for user {}",
                                target_name, username
                            );
                            return Ok(AuthResult::Rejected);
                        }
                        self._auth_accept(user_info.clone(), target_name).await?;
                        Ok(AuthResult::Accepted { user_info })
                    }
                    x => Ok(x),
                }
            }
            AuthSelector::Ticket { secret } => {
                match authorize_ticket(&self.services.db, secret).await? {
                    Some((ticket, user_info)) => {
                        info!("Authorized for {} with a ticket", ticket.target);
                        consume_ticket(&self.services.db, &ticket.id).await?;
                        self._auth_accept(user_info.clone(), &ticket.target).await?;

                        Ok(AuthResult::Accepted { user_info })
                    }
                    None => Ok(AuthResult::Rejected),
                }
            }
        }
    }

    async fn _auth_accept(
        &mut self,
        user_info: AuthStateUserInfo,
        target_name: &str,
    ) -> Result<(), WarpgateError> {
        self.username = Some(user_info.username.clone());
        let _ = self
            .server_handle
            .lock()
            .await
            .set_user_info(user_info.clone())
            .await;

        let target = {
            self.services
                .config_provider
                .lock()
                .await
                .list_targets()
                .await?
                .iter()
                .filter_map(|t| match t.options {
                    TargetOptions::Ssh(ref options) => Some((t, options)),
                    _ => None,
                })
                .find(|(t, _)| t.name == target_name)
                .map(|(t, opt)| (t.clone(), opt.clone()))
        };

        let Some((target, mut ssh_options)) = target else {
            self.target = TargetSelection::NotFound(target_name.to_string());
            warn!("Selected target not found");
            return Ok(());
        };

        // Forward username from the authenticated user to the target, if target has no username
        if ssh_options.username.is_empty() {
            ssh_options.username = user_info.username.to_string();
        }

        let _ = self.server_handle.lock().await.set_target(&target).await;
        self.target = TargetSelection::Found(target, ssh_options);
        Ok(())
    }

    async fn _channel_close(&mut self, server_channel_id: ServerChannelId) -> Result<()> {
        let channel_id = self.map_channel(&server_channel_id)?;
        debug!(channel=%channel_id, "Closing channel");
        // Clean up SFTP tracking for this channel
        self.sftp_channels.remove(&channel_id);
        self.sftp_channel_state.remove(&channel_id);
        self.send_command_and_wait(RCCommand::Channel(channel_id, ChannelOperation::Close))
            .await?;
        Ok(())
    }

    async fn _channel_eof(&mut self, server_channel_id: ServerChannelId) -> Result<()> {
        let channel_id = self.map_channel(&server_channel_id)?;
        debug!(channel=%channel_id, "EOF");
        let _ = self.send_command(RCCommand::Channel(channel_id, ChannelOperation::Eof));
        Ok(())
    }

    pub async fn _channel_signal(
        &mut self,
        server_channel_id: ServerChannelId,
        signal: Sig,
    ) -> Result<()> {
        let channel_id = self.map_channel(&server_channel_id)?;
        debug!(channel=%channel_id, ?signal, "Signal");
        self.send_command_and_wait(RCCommand::Channel(
            channel_id,
            ChannelOperation::Signal(signal),
        ))
        .await?;
        Ok(())
    }

    fn send_command(&mut self, command: RCCommand) -> Result<(), RCCommand> {
        self.rc_tx.send((command, None)).map_err(|e| e.0 .0)
    }

    async fn send_command_and_wait(&mut self, command: RCCommand) -> Result<(), SshClientError> {
        let (tx, rx) = oneshot::channel();
        let mut cmd = match self.rc_tx.send((command, Some(tx))) {
            Ok(_) => PendingCommand::Waiting(rx),
            Err(_) => PendingCommand::Failed,
        };

        loop {
            tokio::select! {
                result = &mut cmd => {
                    return result
                }
                event = self.get_next_event() => {
                    match event {
                        Some(event) => {
                            self.handle_event(event).await.map_err(SshClientError::from)?
                        }
                        None => {Err(SshClientError::MpscError)?}
                    };
                }
            }
        }
    }

    pub async fn _disconnect(&mut self) {
        debug!("Client disconnect requested");
        self.request_disconnect().await;
    }

    async fn request_disconnect(&mut self) {
        debug!("Disconnecting");
        let _ = self.rc_abort_tx.send(());
        if self.rc_state != RCState::NotInitialized && self.rc_state != RCState::Disconnected {
            let _ = self.send_command(RCCommand::Disconnect);
        }
    }

    async fn disconnect_server(&mut self) {
        let all_channels = std::mem::take(&mut self.all_channels);
        let channels = all_channels
            .into_iter()
            .map(|x| self.map_channel_reverse(&x))
            .filter_map(|x| x.ok())
            .collect::<Vec<_>>();

        let _ = self
            .maybe_with_session(|handle| async move {
                for ch in channels {
                    let _ = handle.close(ch.0).await;
                }
                Ok(())
            })
            .await;

        self.session_handle = None;
    }
}

impl Drop for ServerSession {
    fn drop(&mut self) {
        let _ = self.rc_abort_tx.send(());
        info!("Closed session");
        debug!("Dropped");
    }
}

pub enum PendingCommand {
    Waiting(oneshot::Receiver<Result<(), SshClientError>>),
    Failed,
}

impl Future for PendingCommand {
    type Output = Result<(), SshClientError>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            PendingCommand::Waiting(ref mut rx) => match Pin::new(rx).poll(cx) {
                Poll::Ready(result) => {
                    Poll::Ready(result.unwrap_or(Err(SshClientError::MpscError)))
                }
                Poll::Pending => Poll::Pending,
            },
            PendingCommand::Failed => Poll::Ready(Err(SshClientError::MpscError)),
        }
    }
}
