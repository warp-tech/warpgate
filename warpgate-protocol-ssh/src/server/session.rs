use super::service_output::ServiceOutput;
use super::session_handle::SessionHandleCommand;
use crate::compat::ContextExt;
use crate::server::service_output::ERASE_PROGRESS_SPINNER;
use crate::{
    ChannelOperation, ConnectionError, DirectTCPIPParams, PtyRequest, RCCommand, RCEvent, RCState,
    RemoteClient, ServerChannelId, X11Request,
};
use ansi_term::Colour;
use anyhow::{Context, Result};
use bimap::BiMap;
use bytes::{Bytes, BytesMut};
use russh::server::Session;
use russh::{CryptoVec, Sig};
use russh_keys::key::PublicKey;
use russh_keys::PublicKeyBase64;
use std::borrow::Cow;
use std::collections::hash_map::Entry::Vacant;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::{oneshot, Mutex};
use tracing::*;
use uuid::Uuid;
use warpgate_common::auth::AuthSelector;
use warpgate_common::eventhub::{EventHub, EventSender};
use warpgate_common::recordings::{
    ConnectionRecorder, TerminalRecorder, TerminalRecordingStreamId, TrafficConnectionParams,
    TrafficRecorder,
};
use warpgate_common::{
    authorize_ticket, AuthCredential, AuthResult, Secret, Services, SessionId, Target,
    TargetOptions, TargetSSHOptions, WarpgateServerHandle,
};

#[derive(Clone)]
enum TargetSelection {
    None,
    NotFound(String),
    Found(Target, TargetSSHOptions),
}

#[derive(Debug)]
enum Event {
    Command(SessionHandleCommand),
    ConsoleInput(Bytes),
    ServiceOutput(Bytes),
    Client(RCEvent),
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
    rc_tx: UnboundedSender<RCCommand>,
    rc_abort_tx: UnboundedSender<()>,
    rc_state: RCState,
    remote_address: SocketAddr,
    services: Services,
    server_handle: Arc<Mutex<WarpgateServerHandle>>,
    target: TargetSelection,
    traffic_recorders: HashMap<(String, u32), TrafficRecorder>,
    traffic_connection_recorders: HashMap<Uuid, ConnectionRecorder>,
    credentials: Vec<AuthCredential>,
    hub: EventHub<Event>,
    event_sender: EventSender<Event>,
    service_output: ServiceOutput,
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
        server_handle: Arc<Mutex<WarpgateServerHandle>>,
        mut session_handle_rx: UnboundedReceiver<SessionHandleCommand>,
    ) -> Result<Arc<Mutex<Self>>> {
        let id = server_handle.lock().await.id();

        let _span = info_span!("SSH", session=%id);
        let _enter = _span.enter();

        let mut rc_handles = RemoteClient::create(id, services.clone());

        let (hub, event_sender) = EventHub::setup();
        let mut event_sub = hub.subscribe(|_| true).await;

        let (so_tx, mut so_rx) = tokio::sync::mpsc::unbounded_channel();
        let so_sender = event_sender.clone();
        tokio::spawn(async move {
            while let Some(data) = so_rx.recv().await {
                if so_sender
                    .send_once(Event::ServiceOutput(data))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        let this = Self {
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
            credentials: vec![],
            hub,
            event_sender: event_sender.clone(),
            service_output: ServiceOutput::new(Box::new(move |data| {
                so_tx.send(BytesMut::from(data).freeze()).context("x")
            })),
        };

        let this = Arc::new(Mutex::new(this));

        let name = format!("SSH {} session control", id);
        tokio::task::Builder::new().name(&name).spawn({
            let sender = event_sender.clone();
            async move {
                while let Some(command) = session_handle_rx.recv().await {
                    if sender.send_once(Event::Command(command)).await.is_err() {
                        break;
                    }
                }
            }
        });

        let name = format!("SSH {} client events", id);
        tokio::task::Builder::new().name(&name).spawn({
            let sender = event_sender.clone();
            async move {
                while let Some(e) = rc_handles.event_rx.recv().await {
                    if sender.send_once(Event::Client(e)).await.is_err() {
                        break;
                    }
                }
            }
        });

        let name = format!("SSH {} events", id);
        tokio::task::Builder::new().name(&name).spawn({
            let this = Arc::downgrade(&this);
            async move {
                loop {
                    match event_sub.recv().await {
                        Some(Event::Client(RCEvent::Done)) => break,
                        Some(Event::Client(e)) => {
                            debug!(event=?e, "Event");
                            let Some(this) = this.upgrade() else {
                                break;
                            };
                            let this = &mut this.lock().await;
                            if let Err(err) = this.handle_remote_event(e).await {
                                error!("Event handler error: {:?}", err);
                                break;
                            }
                        }
                        Some(Event::Command(command)) => {
                            debug!(?command, "Session control");
                            let Some(this) = this.upgrade() else {
                                break;
                            };
                            let this = &mut this.lock().await;
                            if let Err(err) = this.handle_session_control(command).await {
                                error!("Event handler error: {:?}", err);
                                break;
                            }
                        }
                        Some(Event::ServiceOutput(data)) => {
                            let Some(this) = this.upgrade() else {
                                break;
                            };
                            let this = &mut this.lock().await;
                            let _ = this.emit_pty_output(&data).await;
                        }
                        Some(Event::ConsoleInput(_)) => (),
                        None => break,
                    }
                }
                debug!("No more events");
            }
        });

        Ok(this)
    }

    pub fn make_logging_span(&self) -> tracing::Span {
        match self.username {
            Some(ref username) => info_span!("SSH", session=%self.id, session_username=%username),
            None => info_span!("SSH", session=%self.id),
        }
    }

    fn map_channel(&self, ch: &ServerChannelId) -> Result<Uuid> {
        self.channel_map
            .get_by_left(ch)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Channel not known"))
    }

    fn map_channel_reverse(&self, ch: &Uuid) -> Result<ServerChannelId> {
        self.channel_map
            .get_by_right(ch)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Channel not known"))
    }

    pub async fn emit_service_message(&mut self, msg: &str) -> Result<()> {
        debug!("Service message: {}", msg);

        self.emit_pty_output(
            format!(
                "{}{} {}\r\n",
                ERASE_PROGRESS_SPINNER,
                Colour::Black.on(Colour::White).paint(" Warpgate "),
                msg.replace('\n', "\r\n"),
            )
            .as_bytes(),
        )
        .await
    }

    pub async fn emit_pty_output(&mut self, data: &[u8]) -> Result<()> {
        let channels = self.pty_channels.clone();
        for channel in channels {
            let channel = self.map_channel_reverse(&channel)?;
            self.maybe_with_session(|session| async {
                session
                    .data(channel.0, CryptoVec::from_slice(data))
                    .await
                    .map_err(|_| anyhow::anyhow!("Could not send data"))
            })
            .await?;
        }
        Ok(())
    }

    pub async fn maybe_connect_remote(&mut self) -> Result<()> {
        match self.target.clone() {
            TargetSelection::None => {
                panic!("Target not set");
            }
            TargetSelection::NotFound(name) => {
                self.emit_service_message(&format!("Selected target not found: {name}"))
                    .await?;
                self.disconnect_server().await;
                anyhow::bail!("Target not found: {}", name);
            }
            TargetSelection::Found(target, ssh_options) => {
                if self.rc_state == RCState::NotInitialized {
                    self.rc_state = RCState::Connecting;
                    self.rc_tx.send(RCCommand::Connect(ssh_options))?;
                    self.service_output.show_progress();
                    self.emit_service_message(&format!("Selected target: {}", target.name))
                        .await?;
                }
            }
        }
        Ok(())
    }

    pub async fn handle_session_control(&mut self, command: SessionHandleCommand) -> Result<()> {
        match command {
            SessionHandleCommand::Close => {
                let _ = self.emit_service_message("Session closed by admin").await;
                info!("Session closed by admin");
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
                        self.service_output.hide_progress().await;
                        self.emit_pty_output(
                            format!(
                                "{}{}\r\n",
                                ERASE_PROGRESS_SPINNER,
                                Colour::Black
                                    .on(Colour::Green)
                                    .paint(" ✓ Warpgate connected ")
                            )
                            .as_bytes(),
                        )
                        .await?;
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
                    error => {
                        self.emit_pty_output(
                            format!(
                                "{}{} {}\r\n",
                                ERASE_PROGRESS_SPINNER,
                                Colour::Black.on(Colour::Red).paint(" Connection failed "),
                                error
                            )
                            .as_bytes(),
                        )
                        .await?;
                    }
                }
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

                let server_channel_id = self.map_channel_reverse(&channel)?;
                self.maybe_with_session(|handle| async move {
                    handle
                        .data(server_channel_id.0, CryptoVec::from_slice(&data))
                        .await
                        .map_err(|_| ())
                        .context("failed to send data")
                })
                .await?;
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
            RCEvent::Close(channel) => {
                let server_channel_id = self.map_channel_reverse(&channel)?;
                self.maybe_with_session(|handle| async move {
                    handle
                        .close(server_channel_id.0)
                        .await
                        .context("failed to close ch")
                })
                .await?;
            }
            RCEvent::Eof(channel) => {
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
                self.maybe_with_session(|handle| async move {
                    handle
                        .extended_data(server_channel_id.0, ext, CryptoVec::from_slice(&data))
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
                .await?;
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
        self.service_output.hide_progress().await;
        self.emit_service_message(&format!(
            "There is no trusted {} key for this host.",
            key.name()
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

    pub async fn _channel_open_session(
        &mut self,
        server_channel_id: ServerChannelId,
        session: &mut Session,
    ) -> Result<()> {
        let channel = Uuid::new_v4();
        self.channel_map.insert(server_channel_id, channel);

        info!(%channel, "Opening session channel");
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
        let uuid = Uuid::new_v4();
        self.channel_map.insert(channel, uuid);

        info!(%channel, "Opening direct TCP/IP channel from {}:{} to {}:{}", params.originator_address, params.originator_port, params.host_to_connect, params.port_to_connect);

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
                error!(%channel, ?error, "Failed to record connection setup");
            }
            self.traffic_connection_recorders.insert(uuid, recorder);
        }

        self.all_channels.push(uuid);
        self.session_handle = Some(session.handle());
        self.rc_tx.send(RCCommand::Channel(
            uuid,
            ChannelOperation::OpenDirectTCPIP(params),
        ))?;
        Ok(())
    }

    pub async fn _channel_pty_request(
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
        self.rc_tx.send(RCCommand::Channel(
            channel_id,
            ChannelOperation::RequestPty(request),
        ))?;
        let _ = self
            .session_handle
            .as_mut()
            .unwrap()
            .channel_success(server_channel_id.0)
            .await;
        self.pty_channels.push(channel_id);
        Ok(())
    }

    pub async fn _window_change_request(
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
        self.send_command(RCCommand::Channel(
            channel_id,
            ChannelOperation::ResizePty(request),
        ));
        Ok(())
    }

    pub async fn _channel_exec_request(
        &mut self,
        server_channel_id: ServerChannelId,
        data: Bytes,
    ) -> Result<()> {
        let channel_id = self.map_channel(&server_channel_id)?;
        match std::str::from_utf8(&data) {
            Err(e) => {
                error!(channel=%channel_id, ?data, "Requested exec - invalid UTF-8");
                anyhow::bail!(e)
            }
            Ok::<&str, _>(command) => {
                debug!(channel=%channel_id, %command, "Requested exec");
                let _ = self.maybe_connect_remote().await;
                self.send_command(RCCommand::Channel(
                    channel_id,
                    ChannelOperation::RequestExec(command.to_string()),
                ));

                self.start_terminal_recording(
                    channel_id,
                    format!("exec-channel-{}", server_channel_id.0),
                )
                .await;
            }
        }
        Ok(())
    }

    async fn start_terminal_recording(&mut self, channel_id: Uuid, name: String) {
        match async {
            let mut recorder = self
                .services
                .recordings
                .lock()
                .await
                .start::<TerminalRecorder>(&self.id, name)
                .await?;
            if let Some(request) = self.channel_pty_size_map.get(&channel_id) {
                recorder
                    .write_pty_resize(request.col_width, request.row_height)
                    .await?;
            }
            Ok::<_, anyhow::Error>(recorder)
        }
        .await
        {
            Ok(recorder) => {
                self.channel_recorders.insert(channel_id, recorder);
            }
            Err(error) => {
                error!(channel=%channel_id, ?error, "Failed to start recording");
            }
        }
    }

    pub async fn _channel_x11_request(
        &mut self,
        server_channel_id: ServerChannelId,
        request: X11Request,
    ) -> Result<()> {
        let channel_id = self.map_channel(&server_channel_id)?;
        debug!(channel=%channel_id, "Requested X11");
        let _ = self.maybe_connect_remote().await;
        self.send_command(RCCommand::Channel(
            channel_id,
            ChannelOperation::RequestX11(request),
        ));
        Ok(())
    }

    pub async fn _channel_env_request(
        &mut self,
        server_channel_id: ServerChannelId,
        name: String,
        value: String,
    ) -> Result<()> {
        let channel_id = self.map_channel(&server_channel_id)?;
        debug!(channel=%channel_id, %name, %value, "Environment");
        self.send_command(RCCommand::Channel(
            channel_id,
            ChannelOperation::RequestEnv(name, value),
        ));
        Ok(())
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
                    error!(%host, %port, ?error, "Failed to start recording");
                }
            }
        }
        self.traffic_recorders.get_mut(&(host.clone(), port))
    }

    pub async fn _channel_shell_request(
        &mut self,
        server_channel_id: ServerChannelId,
    ) -> Result<()> {
        let channel_id = self.map_channel(&server_channel_id)?;
        self.rc_tx.send(RCCommand::Channel(
            channel_id,
            ChannelOperation::RequestShell,
        ))?;

        self.start_terminal_recording(channel_id, format!("shell-channel-{}", server_channel_id.0))
            .await;

        info!(%channel_id, "Opening shell");
        let _ = self
            .session_handle
            .as_mut()
            .unwrap()
            .channel_success(server_channel_id.0)
            .await;
        let _ = self.maybe_connect_remote().await;
        Ok(())
    }

    pub async fn _channel_subsystem_request(
        &mut self,
        server_channel_id: ServerChannelId,
        name: String,
    ) -> Result<()> {
        let channel_id = self.map_channel(&server_channel_id)?;
        info!(channel=%channel_id, "Requesting subsystem {}", &name);
        self.send_command(RCCommand::Channel(
            channel_id,
            ChannelOperation::RequestSubsystem(name),
        ));
        Ok(())
    }

    pub async fn _data(&mut self, server_channel_id: ServerChannelId, data: Bytes) -> Result<()> {
        let channel_id = self.map_channel(&server_channel_id)?;
        debug!(channel=%server_channel_id.0, ?data, "Data");
        if self.rc_state == RCState::Connecting && data.get(0) == Some(&3) {
            info!(channel=%channel_id, "User requested connection abort (Ctrl-C)");
            self.request_disconnect().await;
            return Ok(());
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

        self.send_command(RCCommand::Channel(channel_id, ChannelOperation::Data(data)));
        Ok(())
    }

    pub async fn _extended_data(
        &mut self,
        server_channel_id: ServerChannelId,
        code: u32,
        data: BytesMut,
    ) -> Result<()> {
        let channel_id = self.map_channel(&server_channel_id)?;
        debug!(channel=%server_channel_id.0, ?data, "Data");
        self.send_command(RCCommand::Channel(
            channel_id,
            ChannelOperation::ExtendedData {
                ext: code,
                data: data.freeze(),
            },
        ));
        Ok(())
    }

    pub async fn _auth_publickey(
        &mut self,
        ssh_username: String,
        key: &PublicKey,
    ) -> russh::server::Auth {
        let selector: AuthSelector = (&ssh_username).into();

        info!(
            "Public key auth as {:?} with key FP {}",
            selector,
            key.fingerprint()
        );

        self.credentials.push(AuthCredential::PublicKey {
            kind: key.name().to_string(),
            public_key_bytes: Bytes::from(key.public_key_bytes()),
        });

        match self.try_auth(&selector).await {
            Ok(AuthResult::Accepted { .. }) => russh::server::Auth::Accept,
            Ok(AuthResult::Rejected) => russh::server::Auth::Reject,
            Ok(AuthResult::OtpNeeded) => russh::server::Auth::Reject,
            Err(error) => {
                error!(?error, "Failed to verify credentials");
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
        info!("Password key auth as {:?}", selector);

        self.credentials.push(AuthCredential::Password(password));

        match self.try_auth(&selector).await {
            Ok(AuthResult::Accepted { .. }) => russh::server::Auth::Accept,
            Ok(AuthResult::Rejected) => russh::server::Auth::Reject,
            Ok(AuthResult::OtpNeeded) => russh::server::Auth::Reject,
            Err(error) => {
                error!(?error, "Failed to verify credentials");
                russh::server::Auth::Reject
            }
        }
    }

    pub async fn _auth_keyboard_interactive(
        &mut self,
        ssh_username: Secret<String>,
        response: Option<Secret<String>>,
    ) -> russh::server::Auth {
        let selector: AuthSelector = ssh_username.expose_secret().into();
        info!("Keyboard-interactive auth as {:?}", selector);

        if let Some(otp) = response {
            self.credentials.push(AuthCredential::Otp(otp));
        }

        match self.try_auth(&selector).await {
            Ok(AuthResult::Accepted { .. }) => russh::server::Auth::Accept,
            Ok(AuthResult::Rejected) => russh::server::Auth::Reject,
            Ok(AuthResult::OtpNeeded) => russh::server::Auth::Partial {
                name: Cow::Borrowed("Two-factor authentication"),
                instructions: Cow::Borrowed(""),
                prompts: Cow::Owned(vec![(Cow::Borrowed("One-time password: "), true)]),
            },
            Err(error) => {
                error!(?error, "Failed to verify credentials");
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
                    x => Ok(x),
                }
            }
            AuthSelector::Ticket { secret } => {
                match authorize_ticket(&self.services.db, secret).await? {
                    Some(ticket) => {
                        info!("Authorized for {} with a ticket", ticket.target);
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
        info!(username = username, "Authenticated");

        let _ = self
            .server_handle
            .lock()
            .await
            .set_username(username.to_string())
            .await;
        self.username = Some(username.to_string());

        let target = {
            self.services
                .config
                .lock()
                .await
                .store
                .targets
                .iter()
                .filter_map(|t| match t.options {
                    TargetOptions::Ssh(ref options) => Some((t, options)),
                    _ => None,
                })
                .find(|(t, _)| t.name == target_name)
                .map(|(t, opt)| (t.clone(), opt.clone()))
        };

        let Some((target, ssh_options)) = target else {
            self.target = TargetSelection::NotFound(target_name.to_string());
            info!("Selected target not found");
            return;
        };

        let _ = self.server_handle.lock().await.set_target(&target).await;
        self.target = TargetSelection::Found(target, ssh_options);
    }

    pub async fn _channel_close(&mut self, server_channel_id: ServerChannelId) -> Result<()> {
        let channel_id = self.map_channel(&server_channel_id)?;
        debug!(channel=%channel_id, "Closing channel");
        self.send_command(RCCommand::Channel(channel_id, ChannelOperation::Close));
        Ok(())
    }

    pub async fn _channel_eof(&mut self, server_channel_id: ServerChannelId) -> Result<()> {
        let channel_id = self.map_channel(&server_channel_id)?;
        debug!(channel=%channel_id, "EOF");
        self.send_command(RCCommand::Channel(channel_id, ChannelOperation::Eof));
        Ok(())
    }

    // pub async fn _tcpip_forward(&mut self, address: String, port: u32) {
    //     info!(%address, %port, "Remote port forwarding requested");
    //     self.send_command(RCCommand::ForwardTCPIP(address, port));
    // }

    // pub async fn _cancel_tcpip_forward(&mut self, address: String, port: u32) {
    //     info!(%address, %port, "Remote port forwarding cancelled");
    //     self.send_command(RCCommand::CancelTCPIPForward(address, port));
    // }

    pub async fn _channel_signal(
        &mut self,
        server_channel_id: ServerChannelId,
        signal: Sig,
    ) -> Result<()> {
        let channel_id = self.map_channel(&server_channel_id)?;
        debug!(channel=%channel_id, ?signal, "Signal");
        self.send_command(RCCommand::Channel(
            channel_id,
            ChannelOperation::Signal(signal),
        ));
        Ok(())
    }

    fn send_command(&mut self, command: RCCommand) {
        let _ = self.rc_tx.send(command);
    }

    pub async fn _disconnect(&mut self) {
        debug!("Client disconnect requested");
        self.request_disconnect().await;
    }

    async fn request_disconnect(&mut self) {
        debug!("Disconnecting");
        let _ = self.rc_abort_tx.send(());
        if self.rc_state != RCState::NotInitialized && self.rc_state != RCState::Disconnected {
            self.send_command(RCCommand::Disconnect);
        }
    }

    async fn disconnect_server(&mut self) {
        let all_channels = std::mem::take(&mut self.all_channels);
        let channels = all_channels
            .into_iter()
            .map(|x| self.map_channel_reverse(&x))
            .filter(|x| x.is_ok())
            .map(|x| x.unwrap())
            .collect::<Vec<_>>();

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
        info!("Closed connection");
        debug!("Dropped");
    }
}
