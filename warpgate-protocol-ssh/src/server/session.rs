use std::collections::hash_map::Entry::Vacant;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use futures::{Future, FutureExt};
use russh::keys::{PublicKey, PublicKeyBase64};
use russh::server::ChannelOpenHandle;
use russh::{ChannelId, ChannelOpenFailure, MethodKind, MethodSet, Sig};
use termcolor::Color;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::{Mutex, broadcast, oneshot};
use tracing::*;
use url::Url;
use uuid::Uuid;
use warpgate_common::auth::{
    AuthCredential, AuthResult, AuthSelector, AuthState, AuthStateUserInfo, CredentialKind,
};
use warpgate_common::eventhub::{EventHub, EventSender};
use warpgate_common::helpers::username::username_eq_ci;
use warpgate_common::{
    Secret, TargetOptions, TargetSSHOptions, TargetSessionId, UserSessionId, WarpgateError,
};
use warpgate_common_http::ext::construct_external_url;
use warpgate_core::auth::submit_credential;
use warpgate_core::login_protection::FailedAttemptInfo;
use warpgate_core::recordings::{self, TerminalRecorder, TrafficConnectionParams, TrafficRecorder};
use warpgate_core::{
    ApprovedTarget, AuthorizedIdentity, ConfigProvider, Services, TargetAuthorization,
    WarpgateServerHandle, authorize_and_spend_ticket, authorize_for_target,
    authorize_for_target_by_name,
};
use warpgate_db_entities::Parameters;
use warpgate_db_entities::Parameters::SshHostKeyVerificationMode;

use super::channel_registry::{Channel, ChannelRegistry};
use super::channel_writer::ChannelWriter;
use super::event_intake::EventIntake;
use super::russh_handler::ServerHandlerEvent;
use super::service_output::ServiceOutput;
use super::session_handle::SessionHandleCommand;
use crate::server::get_allowed_auth_methods;
use crate::server::service_output::{
    VisualConnectionChainItem, paint_fg, without_control_characters_except_newline,
};
use crate::server::target_menu::{MenuEvent, spawn_target_menu_loop};
use crate::{
    ChannelOperation, ConnectionError, DirectTCPIPParams, PtyRequest, RCCommand, RCCommandReply,
    RCEvent, RCState, RemoteClient, ResolvedSshChainHost, ServerChannelId, SshClientError,
    SshRecordingMetadata, X11Request, client_error_message, resolve_approved_ssh_chain,
};

const EVENT_QUEUE_CAPACITY: usize = 128;

/// Cap on how deep [`ServerSession::send_command_and_wait`] may re-enter itself
/// before it stops dispatching events and buffers them instead. Ordinary
/// traffic stays at a depth of one or two; the cap only exists so a flood of
/// concurrent channel requests can't grow the stack without bound.
const MAX_NESTED_COMMAND_WAITS: usize = 16;

/// How long a teardown waits for queued writes to reach the client before
/// giving up on them.
const DISCONNECT_FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

#[allow(clippy::large_enum_variant)]
enum TargetSelection {
    None,
    Menu,
    NotFound(String),
    /// Carries the capability minted for the target session, so being in this
    /// state means every pre-dial gate ran for exactly the host to be dialed.
    Found(ApprovedTarget<TargetSSHOptions>),
    Connected,
}

#[derive(Debug)]
pub enum Event {
    Command(SessionHandleCommand),
    ServerHandler(ServerHandlerEvent),
    ConsoleInput(Bytes),
    ServiceOutput(Bytes),
    Client(RCEvent),
    MenuRedraw(u16, u16),
    Menu(MenuEvent),
    ServerChannelOpenResult(Uuid, Result<ServerChannelId, russh::Error>),
}

struct PendingKeyboardInteractiveAuth {
    otp_prompt_sent: bool,
    web_approval_retry_count: Option<u8>,
}

enum ProbeState {
    /// New session
    NoAttempt,
    /// Charged with suspicious probing
    Probe {
        username: String,
        method: &'static str,
    },
    /// Vindicated by a successful auth or guilty as charged with a failed login
    Settled,
}

struct CachedSuccessfulTicketAuth {
    ticket: Secret<String>,
    user_info: AuthStateUserInfo,
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub enum TrafficRecorderKey {
    Tcp(String, u32),
    Socket(String),
}

pub struct ServerSession {
    pub id: UserSessionId,
    user_info: Option<AuthStateUserInfo>,
    /// The sealed account-wide proof from the completed [`AuthState`], for the
    /// menu's re-authorization on selection. Deliberately absent for ticket
    /// sessions: a ticket binds one target and grants no account-wide
    /// authorization, so a ticket session reaching the menu fails closed.
    authorized_identity: Option<AuthorizedIdentity>,
    session_handle: Option<russh::server::Handle>,
    channels: ChannelRegistry,
    /// Client-side events for channel ids no registered channel carries yet.
    /// They can only refer to a server-initiated open whose
    /// [`Event::ServerChannelOpenResult`] hasn't been processed — until it is,
    /// the client id (and thus the owning channel) is unknown, so unlike
    /// target-side events they can't be held on the channel itself.
    deferred_server_events: Vec<ServerHandlerEvent>,
    /// Events taken off the queue past [`MAX_NESTED_COMMAND_WAITS`], replayed by
    /// the main event loop once the nesting unwinds.
    pending_events: VecDeque<Event>,
    /// Nesting depth of [`Self::send_command_and_wait`]. A handler dispatched
    /// from a wait can await a command of its own, so the pump re-enters itself
    /// one stack level deeper per concurrent request.
    command_wait_depth: usize,
    rc_tx: UnboundedSender<(RCCommand, Option<RCCommandReply>)>,
    rc_abort_tx: UnboundedSender<()>,
    rc_state: RCState,
    remote_address: SocketAddr,
    services: Services,
    server_handle: Arc<Mutex<WarpgateServerHandle>>,
    target: TargetSelection,
    /// The child session minted by `start_target_session`. Recordings key on
    /// it; shells opened before it exists (the target-selection menu) are
    /// picked up by [`Self::start_recordings_for_pty_channels`] on selection.
    target_session_id: Option<TargetSessionId>,
    traffic_recorders: HashMap<TrafficRecorderKey, TrafficRecorder>,
    hub: EventHub<Event>,
    event_sender: EventSender<Event>,
    intake: EventIntake<Event>,
    service_output: ServiceOutput,
    channel_writer: ChannelWriter,
    /// Cached auth state together with the target name it was created for. The
    /// state's `target_name` is fixed at construction and scopes web approvals,
    /// so it can only be reused for that same target.
    auth_state: Option<(Arc<Mutex<AuthState>>, String)>,
    keyboard_interactive_state: Option<PendingKeyboardInteractiveAuth>,
    cached_successful_ticket_auth: Option<CachedSuccessfulTicketAuth>,
    allowed_auth_methods: MethodSet,
    /// Track the state of a client snooping around pre-auth
    probe: ProbeState,
}

fn session_debug_tag(id: &UserSessionId, remote_address: &SocketAddr) -> String {
    format!("[{id} - {remote_address}]")
}

fn shell_recording_metadata(server_channel_id: ServerChannelId) -> SshRecordingMetadata {
    SshRecordingMetadata::Shell {
        // HACK russh ChannelId is opaque except via Display
        channel: server_channel_id.0.to_string().parse().unwrap_or_default(),
    }
}

fn format_web_auth_instructions(login_url: Option<Url>, identification_string: &str) -> String {
    let spaced_key = identification_string
        .chars()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let url_line = login_url.map(|u| format!("{u}\n")).unwrap_or_default();
    format!(
        "-----------------------------------------------------------------------\n\
         Please verify the SSH authentication request in your browser.\n\
         {url_line}\n\
         Make sure you're seeing this security key: {spaced_key}\n\
         -----------------------------------------------------------------------\n"
    )
}

fn reject_with_allowed_auth_methods(allowed_auth_methods: MethodSet) -> russh::server::Auth {
    russh::server::Auth::Reject {
        proceed_with_methods: Some(allowed_auth_methods),
        partial_success: false,
    }
}

#[cfg(test)]
mod tests {
    use russh::{MethodKind, MethodSet};

    use super::reject_with_allowed_auth_methods;

    #[test]
    fn rejected_public_key_auth_advertises_only_configured_methods() {
        let configured_methods = MethodSet::from(&[MethodKind::PublicKey][..]);
        let auth = reject_with_allowed_auth_methods(configured_methods.clone());

        let russh::server::Auth::Reject {
            proceed_with_methods: Some(advertised_methods),
            ..
        } = auth
        else {
            panic!("expected an authentication rejection with advertised methods");
        };

        assert_eq!(advertised_methods, configured_methods);
        assert!(!advertised_methods.contains(&MethodKind::Password));
        assert!(!advertised_methods.contains(&MethodKind::KeyboardInteractive));
    }
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
    ) -> Result<impl Future<Output = Result<()>> + use<>> {
        let id = server_handle.lock().await.user_session_id();

        let span_ = info_span!("SSH", session=%id);
        let _enter = span_.enter();

        let mut rc_handles = RemoteClient::create(id, services.clone())?;

        let (hub, event_sender) = EventHub::setup(EVENT_QUEUE_CAPACITY);
        let control_events = hub
            .subscribe(|e| !matches!(e, Event::ConsoleInput(_) | Event::Client(_)))
            .await;
        let target_events = hub.subscribe(|e| matches!(e, Event::Client(_))).await;
        let channel_writer = ChannelWriter::new();
        let intake = EventIntake::new(control_events, target_events, channel_writer.data_slots());

        let mut this = Self {
            id,
            user_info: None,
            authorized_identity: None,
            session_handle: None,
            channels: ChannelRegistry::new(),
            deferred_server_events: vec![],
            pending_events: VecDeque::new(),
            command_wait_depth: 0,
            rc_tx: rc_handles.command_tx.clone(),
            rc_abort_tx: rc_handles.abort_tx,
            rc_state: RCState::NotInitialized,
            remote_address,
            services: services.clone(),
            server_handle,
            target: TargetSelection::None,
            target_session_id: None,
            traffic_recorders: HashMap::new(),
            hub,
            event_sender: event_sender.clone(),
            intake,
            service_output: ServiceOutput::new(),
            channel_writer,
            auth_state: None,
            keyboard_interactive_state: None,
            cached_successful_ticket_auth: None,
            allowed_auth_methods: get_allowed_auth_methods(services).await?,
            probe: ProbeState::NoAttempt,
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

        let inactivity_timeout = services.config.lock().await.store.ssh.inactivity_timeout;

        Ok(async move {
            let result = loop {
                if let Some(event) = this.pending_events.pop_front() {
                    if let Err(error) = this.handle_event(event).await {
                        break Err(error);
                    }
                    continue;
                }
                let next_event_fut = this.get_next_event();
                match tokio::time::timeout(inactivity_timeout, next_event_fut).await {
                    Ok(Some(event)) => {
                        if let Err(error) = this.handle_event(event).await {
                            break Err(error);
                        }
                    }
                    Ok(None) => break Ok(()),
                    Err(_) => {
                        info!("Closing the session due to inactivity");
                        let _ = this.emit_service_message("Closing the session due to inactivity");
                        this.request_disconnect();
                        this.disconnect_server().await;
                        break Ok(());
                    }
                }
            };
            debug!("No more events");
            this.settle_failed_probe().await;
            result?;
            Ok::<_, anyhow::Error>(())
        })
    }

    async fn get_next_event(&mut self) -> Option<Event> {
        self.intake.next().await
    }

    /// Based on the global params (#1957)
    fn supported_credential_kinds(&self) -> Vec<CredentialKind> {
        let mut kinds = vec![];
        if self.allowed_auth_methods.contains(&MethodKind::Password) {
            kinds.push(CredentialKind::Password);
        }
        if self.allowed_auth_methods.contains(&MethodKind::PublicKey) {
            kinds.push(CredentialKind::PublicKey);
        }
        if self
            .allowed_auth_methods
            .contains(&MethodKind::KeyboardInteractive)
        {
            kinds.push(CredentialKind::Totp);
            kinds.push(CredentialKind::WebUserApproval);
        }
        kinds
    }

    /// `rate_limit_credential_type` is forwarded to `Services::create_auth_state`
    /// so an unknown username is recorded as a failed attempt for IP blocking —
    /// `None` for benign contexts (public-key offers) that must not be counted.
    async fn get_auth_state(
        &mut self,
        username: &str,
        target_name: &str,
        rate_limit_credential_type: Option<&str>,
    ) -> Result<Arc<Mutex<AuthState>>, WarpgateError> {
        // The cached state may only be reused for the same username *and* the
        // same target: its `target_name` scopes web approvals, so switching
        // targets on one connection must not carry over the previous target's
        // approval.
        if let Some((state, cached_target)) = &self.auth_state
            && cached_target == target_name
            && username_eq_ci(&state.lock().await.user_info().username, username)
        {
            return Ok(state.clone());
        }

        let state = self
            .services
            .create_auth_state(
                &self.id,
                username,
                crate::PROTOCOL_NAME,
                target_name,
                &self.supported_credential_kinds(),
                Some(self.remote_address.ip()),
                rate_limit_credential_type,
            )
            .await?;
        self.auth_state = Some((state.clone(), target_name.to_string()));
        Ok(state)
    }

    /// SSH counts only password/OTP guesses toward rate-limiting — public-key
    /// offers legitimately fail as clients try each agent key in turn, so they
    /// aren't counted as brute-force attempts.
    const fn rate_limited_credential_type(credential: &AuthCredential) -> Option<&'static str> {
        match credential {
            AuthCredential::Password(_) => Some("password"),
            AuthCredential::Otp(_) => Some("otp"),
            _ => None,
        }
    }

    async fn record_failed_login_attempt(&mut self, username: &str, credential_type: &str) {
        self.probe = ProbeState::Settled;
        let _ = self
            .services
            .login_protection
            .record_failed_attempt(FailedAttemptInfo {
                username: username.to_string(),
                remote_ip: self.remote_address.ip(),
                protocol: crate::PROTOCOL_NAME,
                credential_type: credential_type.to_string(),
            })
            .await;
    }

    fn note_probe(&mut self, selector: &AuthSelector, method: &'static str) {
        if let AuthSelector::User { username, .. } = selector
            && !matches!(self.probe, ProbeState::Settled)
        {
            self.probe = ProbeState::Probe {
                username: username.clone(),
                method,
            };
        }
    }

    /// At session end, record a failure if session only did
    /// unsuccessful probes
    async fn settle_failed_probe(&mut self) {
        if self.user_info.is_some() {
            return;
        }
        if let ProbeState::Probe { username, method } = &self.probe {
            let (username, method) = (username.clone(), *method);
            self.record_failed_login_attempt(&username, method).await;
        }
    }

    pub fn make_logging_span(&self) -> tracing::Span {
        let client_ip = self.remote_address.ip().to_string();
        if let Some(user_info) = &self.user_info {
            info_span!("SSH", session=%self.id, session_username=%user_info.username, %client_ip)
        } else {
            info_span!("SSH", session=%self.id, %client_ip)
        }
    }

    fn map_channel(&self, ch: ServerChannelId) -> Result<Uuid, WarpgateError> {
        self.channels
            .uuid_for(ch)
            .ok_or(WarpgateError::InconsistentState(
                "Tried to map unknown channel ID".into(),
            ))
    }

    fn map_channel_reverse(&self, ch: &Uuid) -> Result<ServerChannelId> {
        self.channels
            .get(ch)
            .and_then(Channel::server_id)
            .ok_or_else(|| anyhow::anyhow!("Channel not known"))
    }

    /// The client-facing handle and channel id a target-side channel writes
    /// to. `None` once the client session is gone — everything queued for it
    /// is dropped, so callers just skip the write.
    fn client_channel(&self, channel: &Uuid) -> Result<Option<(russh::server::Handle, ChannelId)>> {
        let server_channel_id = self.map_channel_reverse(channel)?;
        Ok(self
            .session_handle
            .clone()
            .map(|handle| (handle, server_channel_id.0)))
    }

    /// Opens a server->client channel in the background and delivers the
    /// resulting channel id back into the event loop as an event. Awaiting
    /// the client's confirmation inline would deadlock: the russh session
    /// loop might itself be blocked on a handler event that this event loop
    /// hasn't gotten to yet (#1459). The registry entry created here is what
    /// holds the channel's target-side events back until the open resolves.
    fn open_server_channel_in_background(
        &mut self,
        id: Uuid,
        open: impl Future<Output = Result<russh::Channel<russh::server::Msg>, russh::Error>>
        + Send
        + 'static,
    ) {
        self.channels.begin_server_open(id);
        let sender = self.event_sender.clone();
        tokio::spawn(async move {
            let result = open.await.map(|channel| ServerChannelId(channel.id()));
            let _ = sender
                .send_once(Event::ServerChannelOpenResult(id, result))
                .await;
        });
    }

    pub fn emit_pty_output(&self, data: &[u8]) -> Result<()> {
        let channels = self
            .channels
            .values()
            .filter(|c| c.has_pty())
            .filter_map(Channel::server_id)
            .collect::<Vec<_>>();
        for channel in channels {
            if let Some(session) = self.session_handle.clone() {
                self.channel_writer.write(session, channel.0, data, None)?;
            }
        }
        Ok(())
    }

    /// Escaping happens here, at the sink, and not in the callers.
    ///
    /// A fix applied at the point of use only ever covers the points somebody
    /// went looking at — a target name in one message, a certificate's
    /// principals in another. Both PTY sinks escape unconditionally, so a new
    /// call site cannot reopen the hole by forgetting, and Warpgate's own
    /// colour codes are added after the text has been through it.
    pub fn emit_service_message(&self, msg: &str) -> Result<()> {
        // Before the escaping below, not after: this logs the raw message,
        // so a `\n` in a certificate's option name or a Vault error body forges
        // a log record even though the same text reaches the terminal escaped.
        debug!("Service message: {msg:?}");

        let _ = self.emit_pty_output(self.service_output.erase_display().as_bytes());
        let output = format!(
            "{} {}\r\n",
            paint_fg(Color::Blue, false, "● Warpgate:"),
            without_control_characters_except_newline(msg).replace('\n', "\r\n")
        );
        self.emit_pty_output(output.as_bytes())
    }

    pub fn emit_pty_error(&self, msg: &str) -> Result<()> {
        if self.service_output.progress_visible() {
            self.service_output.stop_progress();
            let _ = self.emit_pty_output(self.service_output.erase_display().as_bytes());
        }
        let msg = without_control_characters_except_newline(msg).replace('\n', "\r\n");
        let output = format!("{} {msg}\r\n", paint_fg(Color::Red, false, "● Warpgate:"));
        self.emit_pty_output(output.as_bytes())
    }

    async fn fail_on_channel_writer_error(&mut self, error: anyhow::Error) -> Result<()> {
        warn!(?error, "Failed to send SSH channel data");
        self.request_disconnect();
        self.disconnect_server().await;
        Err(error)
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
        if self.rc_state != RCState::NotInitialized {
            return Ok(());
        }

        let target = match std::mem::replace(&mut self.target, TargetSelection::None) {
            TargetSelection::None => {
                anyhow::bail!("Invalid session state (target not set)")
            }
            TargetSelection::Menu => {
                self.target = TargetSelection::Menu;
                return Ok(());
            }
            TargetSelection::NotFound(name) => {
                self.emit_service_message(&format!("Selected target not found: {name}"))?;
                self.disconnect_server().await;
                anyhow::bail!("Target not found: {name}");
            }
            TargetSelection::Found(approved) => approved,
            TargetSelection::Connected => {
                self.target = TargetSelection::Connected;
                return Ok(());
            }
        };

        self.connect_remote(target).await?;
        self.target = TargetSelection::Connected;
        Ok(())
    }

    /// The dial consumes the capability minted when the target session started.
    async fn connect_remote(&mut self, approved: ApprovedTarget<TargetSSHOptions>) -> Result<()> {
        let ssh_chain = resolve_approved_ssh_chain(&self.services, approved).await?;

        let visual_chain = self.make_visual_connection_chain(&ssh_chain[..]).await?;
        self.rc_state = RCState::Connecting;
        self.send_command(RCCommand::Connect(ssh_chain))
            .map_err(|_| anyhow::anyhow!("cannot send command"))?;
        self.emit_pty_output(b"\r\n")?;
        self.service_output.start_progress(visual_chain).await;
        Ok(())
    }

    async fn make_visual_connection_chain(
        &self,
        ssh_chain: &[ResolvedSshChainHost],
    ) -> Result<Vec<VisualConnectionChainItem>, WarpgateError> {
        let maybe_ext_url =
            construct_external_url(None, &*self.services.config.lock().await, None).await;
        let warpgate_item = match maybe_ext_url {
            Ok(url) => VisualConnectionChainItem::Link {
                text: "Warpgate".into(),
                url: url.to_string(),
            },
            Err(_) => VisualConnectionChainItem::Text("Warpgate".into()),
        };

        let mut display = vec![VisualConnectionChainItem::Text("You".into()), warpgate_item];
        display.extend(
            ssh_chain
                .iter()
                .map(|host| VisualConnectionChainItem::Text(host.name.clone())),
        );

        Ok(display)
    }

    async fn handle_menu_event(&mut self, action: MenuEvent) -> Result<()> {
        match action {
            MenuEvent::Render(data) => {
                self.emit_pty_output(&data)?;
            }
            MenuEvent::Abort => {
                self.emit_service_message("Session closed")?;
                self.request_disconnect();
                self.disconnect_server().await;
            }
            MenuEvent::Selected(target) => {
                // The proof stored when the login's auth state was accepted;
                // absent for ticket sessions, which never reach the menu.
                let identity =
                    self.authorized_identity
                        .clone()
                        .ok_or(WarpgateError::InconsistentState(
                            "No authorized identity".into(),
                        ))?;
                // The menu list was authorized when it was built; permissions
                // may have changed while it was open, so re-check on selection.
                let target_name = target.name.clone();
                let Some(authorization) =
                    authorize_for_target(self.services.config_provider.as_ref(), &identity, target)
                        .await?
                else {
                    warn!(
                        "Target {} not authorized for user {}",
                        target_name, identity.username
                    );
                    self.emit_service_message(&format!("Access to {target_name} denied"))?;
                    self.request_disconnect();
                    self.disconnect_server().await;
                    return Ok(());
                };
                // The menu only lists SSH targets, so this can't refuse a
                // selection it offered.
                let Ok(authorization) = authorization.narrow::<TargetSSHOptions>() else {
                    self.emit_service_message(&format!("Access to {target_name} denied"))?;
                    self.request_disconnect();
                    self.disconnect_server().await;
                    return Ok(());
                };
                let (target_session_id, approved) = self
                    .server_handle
                    .lock()
                    .await
                    .start_target_session(authorization)
                    .await?
                    .admitted()?;
                self.target_session_id = Some(target_session_id);
                self.target = TargetSelection::Found(approved);
                self.start_recordings_for_pty_channels().await;
                // clear screen ; cursor to 1;1
                self.emit_pty_output(b"\x1b[2J\x1b[H")?;
                self.maybe_connect_remote().await?;
            }
        }

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
                    Err(WarpgateError::SessionEnd)?;
                }
                Event::Client(e) => {
                    let e = if let Some(ch) = e.channel()
                        && let Some(channel) = self.channels.get_mut(&ch)
                    {
                        match channel.try_defer(e) {
                            Ok(()) => {
                                debug!(channel=%ch, "Deferring event until the channel open resolves");
                                return Ok(());
                            }
                            Err(e) => e,
                        }
                    } else {
                        e
                    };
                    debug!(event=?e, "Event");
                    let span = self.make_logging_span();
                    if let Err(err) = self.handle_remote_event(e).instrument(span).await {
                        error!("Client event handler error: {:?}", err);
                        // break;
                    }
                }
                Event::ServerHandler(e) => {
                    // An event for a channel id no registered channel carries can
                    // only refer to a pending server-initiated open: the client
                    // learns of such channels no earlier than from the confirmation
                    // that resolves the open. Without any open in flight an unknown
                    // id is simply bogus and is left to the handler to reject.
                    if let Some(ch) = e.existing_channel()
                        && self.channels.uuid_for(ch).is_none()
                        && self.channels.has_opening()
                    {
                        debug!(channel=%ch.0, event=?e, "Deferring event until the channel open resolves");
                        self.deferred_server_events.push(e);
                        return Ok(());
                    }
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
                    if let Some(frame) = self.service_output.take_frame(&data) {
                        let _ = self.emit_pty_output(&frame);
                    }
                }
                Event::Menu(action) => {
                    if let Err(err) = self.handle_menu_event(action).await {
                        error!(?err, "Menu loop action handler error");
                    }
                }
                Event::ServerChannelOpenResult(id, result) => {
                    match result {
                        Ok(server_channel_id) => {
                            if self.channels.assign_server_id(id, server_channel_id) {
                                self.confirm_channel_open(id).await?;
                            } else {
                                debug!(channel=%id, "Open resolved for an already-closed channel");
                                self.replay_deferred_server_events().await?;
                            }
                        }
                        Err(error) => {
                            warn!(channel=%id, ?error, "Failed to open a channel to the client");
                            // Tear the entry down now — its deferred events die
                            // with the open they were waiting on, and the
                            // target's eventual Close reply must find no
                            // Opening entry to be deferred onto.
                            self.channels.close(id);
                            let _ =
                                self.send_command(RCCommand::Channel(id, ChannelOperation::Close));
                            self.replay_deferred_server_events().await?;
                        }
                    }
                }
                Event::MenuRedraw(_, _) | Event::ConsoleInput(_) => (),
            }
            Ok(())
        }
        .boxed()
    }

    /// Confirm `channel` as open and re-dispatch everything held back while its
    /// open was in flight. Events whose channel is still opening are deferred
    /// again by [`Self::handle_event`], so overlapping opens replay safely.
    async fn confirm_channel_open(&mut self, channel: Uuid) -> Result<(), WarpgateError> {
        for event in self.channels.confirm(channel).unwrap_or_default() {
            self.handle_event(Event::Client(event)).await?;
        }
        self.replay_deferred_server_events().await
    }

    async fn replay_deferred_server_events(&mut self) -> Result<(), WarpgateError> {
        for event in std::mem::take(&mut self.deferred_server_events) {
            self.handle_event(Event::ServerHandler(event)).await?;
        }
        Ok(())
    }

    async fn start_target_selection_menu(&self, channel_id: Uuid) -> Result<()> {
        let menu_event_subscription = self
            .hub
            .subscribe(|e| matches!(e, Event::MenuRedraw(_, _) | Event::ConsoleInput(_)))
            .await;

        let username = self
            .user_info
            .as_ref()
            .map(|u| u.username.as_str())
            .ok_or(WarpgateError::InconsistentState("No username".into()))?;

        let ssh_targets = {
            self.services
                .config_provider
                .list_targets()
                .await?
                .into_iter()
                .filter_map(|target| match target.options.clone() {
                    TargetOptions::Ssh(options) => Some((target, options)),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };

        let mut authorized_targets = Vec::new();

        for (target, mut ssh_options) in ssh_targets {
            let is_authorized = self
                .services
                .config_provider
                .authorize_target(username, &target.name)
                .await?;

            if is_authorized {
                if ssh_options.username.is_empty() {
                    ssh_options.username = username.to_string();
                }
                authorized_targets.push((target, ssh_options));
            }
        }

        authorized_targets.sort_by(|(left, _), (right, _)| left.name.cmp(&right.name));

        let (terminal_width, terminal_height) = self
            .channels
            .get(&channel_id)
            .and_then(|c| c.pty_size.as_ref())
            .map_or((220, 24), |r| (r.col_width as u16, r.row_height as u16));

        spawn_target_menu_loop(
            self.id,
            username.to_string(),
            authorized_targets,
            menu_event_subscription,
            self.event_sender.clone(),
            terminal_width,
            terminal_height,
        )?;
        Ok(())
    }

    async fn maybe_start_target_selection_menu(&self, channel_id: Uuid) -> Result<()> {
        if matches!(self.target, TargetSelection::Menu)
            && self.channels.get(&channel_id).is_some_and(Channel::has_pty)
        {
            self.start_target_selection_menu(channel_id).await?;
        }

        Ok(())
    }

    async fn handle_server_handler_event(&mut self, event: ServerHandlerEvent) -> Result<()> {
        match event {
            ServerHandlerEvent::Authenticated(handle) => {
                self.session_handle = Some(handle.0);
            }

            ServerHandlerEvent::ChannelOpenSession(server_channel_id, reply) => {
                info!(channel=%server_channel_id.0, "Opening session channel");
                self._channel_open(
                    server_channel_id,
                    ChannelOperation::OpenShell,
                    None,
                    reply.0,
                )
                .await?;
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
                };
            }

            ServerHandlerEvent::PtyRequest(server_channel_id, request, reply) => {
                let channel_id = self.map_channel(server_channel_id)?;
                let Some(channel_state) = self.channels.get_mut(&channel_id) else {
                    return Err(WarpgateError::InconsistentState(
                        "PTY requested for a channel that was never opened".into(),
                    )
                    .into());
                };
                channel_state.pty_size = Some(request.clone());
                channel_state.audit.on_resize(&request).await;

                self.send_command_and_wait(RCCommand::Channel(
                    channel_id,
                    ChannelOperation::RequestPty(request),
                ))
                .await?;
                let handle = self
                    .session_handle
                    .clone()
                    .context("Invalid session state")?;
                let _ = self
                    .channel_writer
                    .channel_success(handle, server_channel_id.0);
                // Waiting for the target above pumps the event loop, so the
                // channel may have been closed in the meantime — hence the
                // re-lookup instead of holding the entry across the await.
                if let Some(channel_state) = self.channels.get_mut(&channel_id) {
                    channel_state.mark_pty();
                }
                let _ = reply.send(());
            }

            ServerHandlerEvent::ShellRequest(server_channel_id, reply) => {
                let channel_id = self.map_channel(server_channel_id)?;
                self.maybe_connect_remote().await?;
                self.maybe_start_target_selection_menu(channel_id).await?;

                let _ = self.send_command(RCCommand::Channel(
                    channel_id,
                    ChannelOperation::RequestShell,
                ));

                self.start_terminal_recording(
                    channel_id,
                    shell_recording_metadata(server_channel_id),
                )
                .await;
                self.maybe_start_command_detector(channel_id);

                info!(%channel_id, "Opening shell");

                let handle = self
                    .session_handle
                    .clone()
                    .context("Invalid session state")?;
                let _ = self
                    .channel_writer
                    .channel_success(handle, server_channel_id.0);

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

            ServerHandlerEvent::AuthKeyboardInteractive(username, responses, reply) => {
                let _ = reply.send(self._auth_keyboard_interactive(username, responses).await?);
            }

            ServerHandlerEvent::Data(channel, data, reply) => {
                self._data(channel, data).await?;
                let _ = reply.send(());
            }

            ServerHandlerEvent::ExtendedData(channel, data, code, reply) => {
                self._extended_data(channel, code, data)?;
                let _ = reply.send(());
            }

            ServerHandlerEvent::ChannelClose(channel, reply) => {
                self._channel_close(channel).await?;
                let _ = reply.send(());
            }

            ServerHandlerEvent::ChannelEof(channel, reply) => {
                self._channel_eof(channel)?;
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

            ServerHandlerEvent::ExecRequest(channel, data, reply) => {
                self._channel_exec_request(channel, data).await?;
                let _ = reply.send(true);
            }

            ServerHandlerEvent::ChannelOpenDirectTcpIp(channel, params, reply) => {
                self._channel_open_direct_tcpip(channel, params, reply.0)
                    .await?;
            }

            ServerHandlerEvent::ChannelOpenDirectStreamlocal(channel, path, reply) => {
                self._channel_open_direct_streamlocal(channel, path, reply.0)
                    .await?;
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
                self._tcpip_forward(address, port).await?;
                let _ = reply.send(true);
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
                let _ = self.emit_service_message("Session closed by admin");
                info!("Session closed by admin");
                self.request_disconnect();
                self.disconnect_server().await;
            }
        }
        Ok(())
    }

    pub async fn handle_remote_event(&mut self, event: RCEvent) -> Result<()> {
        match event {
            RCEvent::HopConnected => {
                self.service_output.notify_hop_connected().await;
            }
            RCEvent::State(state) => {
                self.rc_state = state;
                match &self.rc_state {
                    RCState::Connected => {
                        let msg = self
                            .service_output
                            .render_final_success_static_frame()
                            .await;
                        let _ = self.emit_pty_output(msg.as_bytes());
                    }
                    RCState::Disconnected => {
                        self.service_output.stop_progress();
                        self.disconnect_server().await;
                    }
                    _ => {}
                }
            }
            RCEvent::ConnectionError(error) => {
                self.service_output.stop_progress();

                match error {
                    ConnectionError::HostKeyMismatch {
                        received_key_type,
                        received_key_base64,
                        known_key_type,
                        known_key_base64,
                    } => {
                        let _ = self.emit_pty_error("Host key doesn't match the stored one.");
                        let msg = format!(
                            concat!("Stored key   ({}): {}\n", "Received key ({}): {}",),
                            known_key_type,
                            known_key_base64,
                            received_key_type,
                            received_key_base64
                        );
                        self.emit_service_message(&msg)?;
                        self.emit_service_message(
                            "If you know that the key is correct (e.g. it has been changed),",
                        )?;
                        self.emit_service_message(
                            "you can remove the old key in the Warpgate management UI and try again",
                        )?;
                    }
                    ConnectionError::Authentication(ref reason) => {
                        // The reason is what tells a wrong credential apart from
                        // a target whose clock disagrees, which is the most
                        // common cause of a short-lived certificate being
                        // refused, so it must reach the user and not stop at
                        // the server log.
                        let _ = self.emit_pty_error(&format!(
                            "SSH target rejected Warpgate's authentication request: {reason}"
                        ));
                    }
                    error => {
                        tracing::error!(%error, "Target connection failed");
                        // `client_message()` and not `{error}`: the full text is
                        // for the log above, and carries Vault URLs and role
                        // names a connected user must not be handed.
                        let _ = self.emit_pty_error(&format!(
                            "Target connection failed: {}",
                            error.client_message()
                        ));
                    }
                }
            }
            RCEvent::Error(e) => {
                self.service_output.stop_progress();
                // The full error to the log, a constant to the terminal. The
                // detail is what an operator needs and what a connected user
                // must not be handed; printing `{e}` gave it to the user and
                // was the one path to this sink that no round of hardening had
                // touched.
                error!(error=%e, "Client session error");
                let _ = self.emit_pty_error(client_error_message(&e));
                self.disconnect_server().await;
            }
            RCEvent::Output(channel, data) => {
                if let Some(channel_state) = self.channels.get_mut(&channel) {
                    channel_state.audit.on_output(&data).await;

                    if let Some(recorder) = channel_state.traffic_recorder.as_mut()
                        && let Err(error) = recorder.write_rx(&data).await
                    {
                        error!(%channel, ?error, "Failed to record traffic data");
                        channel_state.traffic_recorder = None;
                    }
                }

                let slot = self.intake.take_slot();
                if let Some((handle, id)) = self.client_channel(&channel)?
                    && let Err(error) = self.channel_writer.write(handle, id, data, slot)
                {
                    return self.fail_on_channel_writer_error(error).await;
                }
            }
            RCEvent::Success(channel) => {
                if let Some((handle, id)) = self.client_channel(&channel)? {
                    self.channel_writer.channel_success(handle, id)?;
                }
            }
            RCEvent::ChannelFailure(channel) => {
                if let Some((handle, id)) = self.client_channel(&channel)? {
                    self.channel_writer.channel_failure(handle, id)?;
                }
            }
            RCEvent::Close(channel) => {
                if let Ok(Some((handle, id))) = self.client_channel(&channel) {
                    let _ = self.channel_writer.close(handle, id);
                }
                self.channels.close(channel);
            }
            RCEvent::Eof(channel) => {
                if let Some((handle, id)) = self.client_channel(&channel)? {
                    self.channel_writer.eof(handle, id)?;
                }
            }
            RCEvent::ExitStatus(channel, code) => {
                if let Some((handle, id)) = self.client_channel(&channel)? {
                    self.channel_writer.exit_status(handle, id, code)?;
                }
            }
            RCEvent::ExitSignal {
                channel,
                signal_name,
                core_dumped,
                error_message,
                lang_tag,
            } => {
                if let Some((handle, id)) = self.client_channel(&channel)? {
                    self.channel_writer.exit_signal(
                        handle,
                        id,
                        signal_name,
                        core_dumped,
                        error_message,
                        lang_tag,
                    )?;
                }
            }
            RCEvent::ExtendedData { channel, data, ext } => {
                if let Some(channel_state) = self.channels.get_mut(&channel) {
                    channel_state.audit.on_error_output(&data).await;
                }
                let slot = self.intake.take_slot();
                if let Some((handle, id)) = self.client_channel(&channel)?
                    && let Err(error) = self
                        .channel_writer
                        .write_extended(handle, id, ext, data, slot)
                {
                    return self.fail_on_channel_writer_error(error).await;
                }
            }
            RCEvent::Done | RCEvent::HostKeyReceived(..) => {}
            RCEvent::HostKeyUnknown(key, _, _, reply) => {
                self.handle_unknown_host_key(key, reply).await?;
            }
            RCEvent::ForwardedTcpIp(id, params) => {
                if let Some(session) = self.session_handle.clone() {
                    let open_params = params.clone();
                    self.open_server_channel_in_background(id, async move {
                        session
                            .channel_open_forwarded_tcpip(
                                open_params.connected_address,
                                open_params.connected_port,
                                open_params.originator_address,
                                open_params.originator_port,
                            )
                            .await
                    });

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
                        if let Some(channel_state) = self.channels.get_mut(&id) {
                            channel_state.traffic_recorder = Some(recorder);
                        }
                    }
                }
            }
            RCEvent::ForwardedStreamlocal(id, params) => {
                if let Some(session) = self.session_handle.clone() {
                    let socket_path = params.socket_path.clone();
                    self.open_server_channel_in_background(id, async move {
                        session
                            .channel_open_forwarded_streamlocal(socket_path)
                            .await
                    });

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
                        if let Some(channel_state) = self.channels.get_mut(&id) {
                            channel_state.traffic_recorder = Some(recorder);
                        }
                    }
                }
            }
            RCEvent::ForwardedAgent(id) => {
                if let Some(session) = self.session_handle.clone() {
                    self.open_server_channel_in_background(id, async move {
                        session.channel_open_agent().await
                    });
                }
            }
            RCEvent::X11(id, originator_address, originator_port) => {
                if let Some(session) = self.session_handle.clone() {
                    self.open_server_channel_in_background(id, async move {
                        session
                            .channel_open_x11(originator_address, originator_port)
                            .await
                    });
                }
            }
        }
        Ok(())
    }

    async fn handle_unknown_host_key(
        &self,
        key: PublicKey,
        reply: oneshot::Sender<bool>,
    ) -> Result<()> {
        let mode = Parameters::Entity::get(&self.services.db)
            .await?
            .ssh_host_key_verification;

        // `Ignore` never gets here - the key is accepted without a lookup.
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

        self.service_output.stop_progress();

        if !self.channels.values().any(Channel::has_pty) {
            warn!(
                "Target host key is not trusted, but there is no active PTY channel to show the trust prompt on."
            );
            warn!(
                "Connect to this target with an interactive session once to accept the host key."
            );
            self.request_disconnect();
            anyhow::bail!("No PTY channel to show an interactive prompt on")
        }

        self.emit_service_message(&format!(
            "Host key ({}): {}",
            key.algorithm(),
            key.public_key_base64()
        ))?;
        self.emit_service_message(&format!(
            "There is no trusted {} key for this host.",
            key.algorithm()
        ))?;
        self.emit_service_message("Trust this key? (y/n)")?;

        let mut sub = self
            .hub
            .subscribe(|e| matches!(e, Event::ConsoleInput(_)))
            .await;

        let service_output = self.service_output.clone();
        tokio::spawn(async move {
            loop {
                match sub.recv().await {
                    Some(Event::ConsoleInput(data)) => {
                        if &data[..] == b"y" {
                            let _ = reply.send(true);
                            break;
                        } else if &data[..] == b"n" {
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

    async fn _channel_open_direct_tcpip(
        &mut self,
        channel: ServerChannelId,
        params: DirectTCPIPParams,
        open_handle: ChannelOpenHandle,
    ) -> Result<()> {
        info!(%channel, "Opening direct TCP/IP channel from {}:{} to {}:{}", params.originator_address, params.originator_port, params.host_to_connect, params.port_to_connect);
        let key = TrafficRecorderKey::Tcp(params.host_to_connect.clone(), params.port_to_connect);
        let metadata = SshRecordingMetadata::DirectTcpIp {
            host: params.host_to_connect.clone(),
            port: params.port_to_connect as u16,
        };
        #[allow(clippy::unwrap_used)]
        let connection_params = TrafficConnectionParams::Tcp {
            dst_addr: Ipv4Addr::from_str("2.2.2.2").unwrap(),
            dst_port: params.port_to_connect as u16,
            src_addr: Ipv4Addr::from_str("1.1.1.1").unwrap(),
            src_port: params.originator_port as u16,
        };
        // Unlike a session channel — whose later shell/exec/subsystem request
        // dials the target — a direct channel is the whole interaction, so the
        // connection must be initiated here.
        let _ = self.maybe_connect_remote().await;
        self._channel_open(
            channel,
            ChannelOperation::OpenDirectTCPIP(params),
            Some((key, metadata, connection_params)),
            open_handle,
        )
        .await
    }

    async fn _channel_open_direct_streamlocal(
        &mut self,
        channel: ServerChannelId,
        path: String,
        open_handle: ChannelOpenHandle,
    ) -> Result<()> {
        info!(%channel, "Opening direct streamlocal channel to {}", path);
        let key = TrafficRecorderKey::Socket(path.clone());
        let metadata = SshRecordingMetadata::DirectSocket { path: path.clone() };
        let connection_params = TrafficConnectionParams::Socket {
            socket_path: path.clone(),
        };
        let _ = self.maybe_connect_remote().await;
        self._channel_open(
            channel,
            ChannelOperation::OpenDirectStreamlocal(path),
            Some((key, metadata, connection_params)),
            open_handle,
        )
        .await
    }

    /// Open a client-initiated channel towards the target and send the client
    /// its open confirmation from here, the session task. The
    /// [`ChannelState::Opening`] entry holds the target's output back until
    /// `accept()` has queued the confirmation, so server-speaks-first bytes
    /// never precede `CHANNEL_OPEN_CONFIRMATION` (#2328).
    async fn _channel_open(
        &mut self,
        channel: ServerChannelId,
        operation: ChannelOperation,
        recording: Option<(
            TrafficRecorderKey,
            SshRecordingMetadata,
            TrafficConnectionParams,
        )>,
        open_handle: ChannelOpenHandle,
    ) -> Result<()> {
        let uuid = self.channels.begin_client_open(channel);

        match self
            .send_command_and_wait(RCCommand::Channel(uuid, operation))
            .await
        {
            Ok(()) => {
                open_handle.accept().await;

                // The recorder is attached before the deferred output is
                // replayed, so the target's first bytes are recorded too.
                if let Some((key, metadata, connection_params)) = recording {
                    let recorder = self.traffic_recorder_for(key, metadata).await;
                    if let Some(recorder) = recorder {
                        let mut recorder = recorder.connection(connection_params);
                        if let Err(error) = recorder.write_connection_setup().await {
                            error!(%channel, ?error, "Failed to record connection setup");
                        }
                        if let Some(channel_state) = self.channels.get_mut(&uuid) {
                            channel_state.traffic_recorder = Some(recorder);
                        }
                    }
                }

                self.confirm_channel_open(uuid).await?;
                Ok(())
            }
            Err(SshClientError::Russh(russh::Error::ChannelOpenFailure(_))) => {
                open_handle.reject(ChannelOpenFailure::ConnectFailed).await;
                self.channels.close(uuid);
                Ok(())
            }
            // Dropping `open_handle` auto-rejects the open, so the client always
            // gets a reply even on unexpected errors.
            Err(x) => {
                self.channels.close(uuid);
                Err(x.into())
            }
        }
    }

    async fn _window_change_request(
        &mut self,
        server_channel_id: ServerChannelId,
        request: PtyRequest,
    ) -> Result<()> {
        let channel_id = self.map_channel(server_channel_id)?;
        let Some(channel_state) = self.channels.get_mut(&channel_id) else {
            return Err(WarpgateError::InconsistentState(
                "Window change for a channel that was never opened".into(),
            )
            .into());
        };
        channel_state.pty_size = Some(request.clone());
        channel_state.audit.on_resize(&request).await;

        if matches!(self.target, TargetSelection::Menu) {
            let _ = self
                .event_sender
                .try_send_once(Event::MenuRedraw(
                    request.col_width as u16,
                    request.row_height as u16,
                ))
                .await;
        }

        if self.rc_state != RCState::Connected {
            return Ok(());
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
        let channel_id = self.map_channel(server_channel_id)?;
        let command = std::str::from_utf8(&data).inspect_err(|_| {
            error!(channel=%channel_id, ?data, "Requested exec - invalid UTF-8");
        })?;
        info!(channel=%channel_id, command=%command, "Exec command");

        let is_scp = command == "scp" || command.starts_with("scp ");
        let _ = self.maybe_connect_remote().await;
        self.maybe_start_target_selection_menu(channel_id).await?;
        let _ = self.send_command(RCCommand::Channel(
            channel_id,
            ChannelOperation::RequestExec(command.to_string()),
        ));

        let should_record = if is_scp {
            let db = &self.services.db;
            let should_record = Parameters::Entity::get(db)
                .await
                .map_or(true, |p| p.record_scp);

            if !should_record {
                info!(channel=%channel_id, "Not recording SCP exec session, command was '{command}'");
            }

            should_record
        } else {
            true
        };

        if should_record {
            self.start_terminal_recording(
                channel_id,
                SshRecordingMetadata::Exec {
                    // HACK russh ChannelId is opaque except via Display
                    channel: server_channel_id.0.to_string().parse().unwrap_or_default(),
                },
            )
            .await;
        }
        Ok(())
    }

    async fn start_terminal_recording(&mut self, channel_id: Uuid, metadata: SshRecordingMetadata) {
        // A recording row must reference a target session. Before one exists
        // (the target-selection menu is open) nothing is recorded; the menu's
        // shell channels are swept up by `start_recordings_for_pty_channels`
        // when a target is selected.
        let Some(target_session_id) = self.target_session_id else {
            return;
        };
        let recorder = async {
            let recorder = self
                .services
                .recordings
                .start::<TerminalRecorder, _>(&target_session_id, None, metadata)
                .await?;
            if let Some(request) = self
                .channels
                .get(&channel_id)
                .and_then(|c| c.pty_size.as_ref())
            {
                recorder
                    .write_pty_resize(request.col_width, request.row_height)
                    .await?;
            }
            Ok::<_, recordings::Error>(recorder)
        }
        .await;
        match recorder {
            Ok(recorder) => {
                // Starting the recording awaits, so the channel can be gone by
                // now — e.g. target selection failed and tore the session down.
                if let Some(channel_state) = self.channels.get_mut(&channel_id) {
                    channel_state.audit.set_recorder(recorder);
                } else {
                    debug!(channel=%channel_id, "Recording started for a channel that is already gone");
                }
            }
            Err(error) => match error {
                recordings::Error::Disabled => (),
                error => error!(channel=%channel_id, ?error, "Failed to start recording"),
            },
        }
    }

    /// Starts terminal recordings for the shells opened while no target
    /// session existed yet — the target-selection menu runs in a PTY shell,
    /// so PTY presence identifies them. Called wherever a target session
    /// starts; channels opening later record via their own shell request.
    async fn start_recordings_for_pty_channels(&mut self) {
        let channels: Vec<(Uuid, SshRecordingMetadata)> = self
            .channels
            .iter()
            .filter(|(_, channel)| channel.has_pty())
            .filter_map(|(id, channel)| Some((*id, shell_recording_metadata(channel.server_id()?))))
            .collect();
        for (channel_id, metadata) in channels {
            self.start_terminal_recording(channel_id, metadata).await;
        }
    }

    fn maybe_start_command_detector(&mut self, channel_id: Uuid) {
        let Some(channel_state) = self.channels.get_mut(&channel_id) else {
            return;
        };
        if !channel_state.has_pty() {
            return;
        }
        let (cols, rows) = channel_state
            .pty_size
            .as_ref()
            .map_or((80, 24), PtyRequest::screen_size);
        channel_state.audit.start_command_detection(cols, rows);
    }

    async fn _channel_x11_request(
        &mut self,
        server_channel_id: ServerChannelId,
        request: X11Request,
    ) -> Result<()> {
        let channel_id = self.map_channel(server_channel_id)?;
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
        let channel_id = self.map_channel(server_channel_id)?;
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
        // Traffic flows only through a connected target, so the target session
        // always exists by now.
        let Some(target_session_id) = self.target_session_id else {
            error!(?key, "No target session for traffic recording");
            return None;
        };
        if let Vacant(e) = self.traffic_recorders.entry(key.clone()) {
            match self
                .services
                .recordings
                .start(&target_session_id, None, metadata)
                .await
            {
                Ok(recorder) => {
                    e.insert(recorder);
                }
                Err(recordings::Error::Disabled) => (),
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
        let channel_id = self.map_channel(server_channel_id)?;
        info!(channel=%channel_id, "Requesting subsystem {}", &name);
        let _ = self.maybe_connect_remote().await;
        self.send_command_and_wait(RCCommand::Channel(
            channel_id,
            ChannelOperation::RequestSubsystem(name),
        ))
        .await?;
        Ok(())
    }

    async fn _data(&mut self, server_channel_id: ServerChannelId, data: Bytes) -> Result<()> {
        let channel_id = self.map_channel(server_channel_id)?;
        debug!(channel=%server_channel_id.0, ?data, "Data");
        if self.rc_state == RCState::Connecting && data.first() == Some(&3) {
            info!(channel=%channel_id, "User requested connection abort (Ctrl-C)");
            self.request_disconnect();
            return Ok(());
        }

        if let Some(channel_state) = self.channels.get_mut(&channel_id) {
            channel_state.audit.on_input(&data).await;

            if let Some(recorder) = channel_state.traffic_recorder.as_mut()
                && let Err(error) = recorder.write_tx(&data).await
            {
                error!(channel=%channel_id, ?error, "Failed to record traffic data");
                channel_state.traffic_recorder = None;
            }
        }

        if self.channels.get(&channel_id).is_some_and(Channel::has_pty) {
            let _ = self
                .event_sender
                .try_send_once(Event::ConsoleInput(data.clone()))
                .await;
        }

        // While the target selection menu is open, keystrokes drive the menu
        // (handled above) and there's no target to forward them to.
        // Otherwise forward the data even before the target connection is
        // established: the remote client buffers channel operations and
        // replays them in order once connected, so early stdin (e.g. rsync,
        // scp or Ansible pipelining payloads sent right after the exec
        // request) must not be dropped (#2065).
        if matches!(self.target, TargetSelection::Menu) {
            return Ok(());
        }

        let _ = self.send_command(RCCommand::Channel(channel_id, ChannelOperation::Data(data)));
        Ok(())
    }

    fn _extended_data(
        &self,
        server_channel_id: ServerChannelId,
        code: u32,
        data: Bytes,
    ) -> Result<()> {
        let channel_id = self.map_channel(server_channel_id)?;
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
        let channel_id = self.map_channel(server_channel_id)?;
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
        self.note_probe(&selector, "public_key");

        if !self.allowed_auth_methods.contains(&MethodKind::PublicKey) {
            warn!("Client attempted public key auth even though it was not advertised");
            return russh::server::Auth::reject();
        }

        // Tickets aren't authenticated with public keys, and the eager auth path
        // consumes a ticket use. Running it here — during the unauthenticated
        // offer/query phase — would drain the ticket before the client actually
        // authenticates, so reject and let auth proceed via another method.
        if let AuthSelector::Ticket { .. } = selector {
            return russh::server::Auth::reject();
        }

        if matches!(
            self.try_validate_public_key_offer(
                &selector,
                Some(AuthCredential::PublicKey {
                    kind: key.algorithm(),
                    public_key_bytes: Bytes::from(key.public_key_bytes()),
                }),
            )
            .await,
            Ok(true)
        ) {
            return russh::server::Auth::Accept;
        }

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
        self.note_probe(&selector, "public_key");

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
                    .update_public_key_last_used(key.clone())
                    .await
                {
                    warn!(?err, "Failed to update last_used for public key");
                }
                russh::server::Auth::Accept
            }
            Ok(AuthResult::Rejected) => {
                reject_with_allowed_auth_methods(self.allowed_auth_methods.clone())
            }
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
        self.note_probe(&selector, "password");

        if !self.allowed_auth_methods.contains(&MethodKind::Password) {
            warn!("Client attempted password auth even though it was not advertised");
            if let AuthSelector::User { username, .. } = &selector {
                self.record_failed_login_attempt(username, "password").await;
            }
            return russh::server::Auth::reject();
        }

        let result = self
            .try_auth_lazy(&selector, Some(AuthCredential::Password(password)))
            .await;

        match result {
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
        responses: Vec<Secret<String>>,
    ) -> Result<russh::server::Auth> {
        let selector: AuthSelector = ssh_username.expose_secret().into();
        info!("Keyboard-interactive auth as {:?}", selector);
        self.note_probe(&selector, "keyboard_interactive");

        if !self
            .allowed_auth_methods
            .contains(&MethodKind::KeyboardInteractive)
        {
            warn!("Client attempted keyboard-interactive auth even though it was not advertised");
            return Ok(russh::server::Auth::reject());
        }

        let keyboard_interactive_state = self.keyboard_interactive_state.take();
        let maybe_otp_cred = keyboard_interactive_state.as_ref().and_then(|s| {
            if s.otp_prompt_sent {
                responses.into_iter().next().map(AuthCredential::Otp)
            } else {
                None
            }
        });
        let pending_web_auth_retries =
            keyboard_interactive_state.and_then(|s| s.web_approval_retry_count);

        Ok(match self.try_auth_lazy(&selector, maybe_otp_cred).await {
            Ok(AuthResult::Accepted { .. }) => russh::server::Auth::Accept,
            Ok(AuthResult::Rejected) => russh::server::Auth::reject(),
            Ok(AuthResult::Need(kinds)) => {
                let mut auth_name = "Warpgate authentication".to_string();
                let mut auth_instructions = String::new();
                let mut auth_prompts = vec![];

                let Some((auth_state, _)) = self.auth_state.as_ref() else {
                    return Ok(russh::server::Auth::Reject {
                        proceed_with_methods: None,
                        partial_success: false,
                    });
                };

                let mut next_pending = PendingKeyboardInteractiveAuth {
                    otp_prompt_sent: false,
                    web_approval_retry_count: None,
                };

                if kinds.contains(&CredentialKind::Totp) {
                    next_pending.otp_prompt_sent = true;
                    auth_name = "Two-factor authentication".into();
                    auth_prompts.push(("One-time password: ".into(), true));
                }

                if kinds.contains(&CredentialKind::WebUserApproval) {
                    let identification_string =
                        auth_state.lock().await.identification_string().to_owned();

                    let ext_url =
                        construct_external_url(None, &*self.services.config.lock().await, None)
                            .await
                            .inspect_err(|error| {
                                warn!(?error, "Failed to construct external URL");
                            })
                            .ok();

                    let auth_state = auth_state.lock().await;
                    let login_url =
                        ext_url.map(|ext_url| auth_state.construct_web_approval_url(ext_url));

                    auth_instructions.push_str(&format_web_auth_instructions(
                        login_url,
                        &identification_string,
                    ));
                    auth_prompts.push(("Press Enter when done: ".into(), true));

                    #[allow(clippy::items_after_statements)]
                    const MAX_RETRIES: u8 = 3;
                    if let Some(retries) = pending_web_auth_retries {
                        if retries >= MAX_RETRIES {
                            drop(auth_state);
                            self.auth_state = None;
                            return Ok(russh::server::Auth::reject());
                        }

                        auth_instructions.push_str(
                            "\n[!] Browser authentication was not confirmed, please try again.\n",
                        );
                        next_pending.web_approval_retry_count = Some(retries + 1);
                    } else {
                        next_pending.web_approval_retry_count = Some(0);
                    }
                }

                if auth_prompts.is_empty() {
                    russh::server::Auth::Reject {
                        proceed_with_methods: None,
                        partial_success: false,
                    }
                } else {
                    self.keyboard_interactive_state = Some(next_pending);
                    russh::server::Auth::Partial {
                        name: auth_name.into(),
                        instructions: auth_instructions.into(),
                        prompts: auth_prompts.into(),
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
        })
    }

    fn get_remaining_auth_methods(&self, kinds: HashSet<CredentialKind>) -> MethodSet {
        let mut m = MethodSet::empty();

        for cred_kind in kinds {
            let method_kind = match cred_kind {
                CredentialKind::Password => MethodKind::Password,
                CredentialKind::Totp | CredentialKind::WebUserApproval | CredentialKind::Sso => {
                    MethodKind::KeyboardInteractive
                }
                CredentialKind::PublicKey => MethodKind::PublicKey,
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
        &self,
        selector: &AuthSelector,
        credential: Option<AuthCredential>,
    ) -> Result<bool> {
        match selector {
            AuthSelector::User { username, .. } => {
                let cp = self.services.config_provider.clone();

                if let Some(credential) = credential {
                    return Ok(cp.validate_credential(username, &credential).await?);
                }

                Ok(false)
            }
            AuthSelector::Ticket { .. } => Ok(false),
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
        let remote_ip = self.remote_address.ip();

        // Login protection applies to every auth path, tickets included:
        // reject attempts from blocked IPs before evaluating anything.
        if self
            .services
            .login_protection
            .check_ip_blocked(&remote_ip)
            .await?
            .is_some()
        {
            warn!(ip = %remote_ip, "SSH auth from blocked IP");
            return Ok(AuthResult::Rejected);
        }

        match selector {
            AuthSelector::User {
                username,
                target_name,
            } => {
                if self
                    .services
                    .login_protection
                    .check_user_locked(username)
                    .await?
                    .is_some()
                {
                    warn!(username = %username, "SSH auth for locked user");
                    return Ok(AuthResult::Rejected);
                }

                let state_arc = self
                    .get_auth_state(
                        username,
                        target_name,
                        credential
                            .as_ref()
                            .and_then(Self::rate_limited_credential_type),
                    )
                    .await?;
                let mut state = state_arc.lock().await;

                if let Some(credential) = credential {
                    let credential_type = Self::rate_limited_credential_type(&credential);
                    let outcome = submit_credential(
                        &mut state,
                        credential,
                        self.services.config_provider.as_ref(),
                        &self.services.login_protection,
                    )
                    .await?;

                    if outcome.is_valid() {
                        self.probe = ProbeState::Settled;
                    } else if let Some(credential_type) = credential_type {
                        self.record_failed_login_attempt(username, credential_type)
                            .await;
                    }
                }

                if matches!(state.verify(), AuthResult::Need(ref kinds) if kinds.contains(&CredentialKind::WebUserApproval))
                {
                    drop(state);
                    self.services.try_web_approval_bypass(&state_arc).await?;
                    state = state_arc.lock().await;
                }

                let user_auth_result = state.verify();

                match user_auth_result {
                    AuthResult::Accepted { user_info } => {
                        // Successful auth clears the failed-attempt counters.
                        let _ = self
                            .services
                            .login_protection
                            .clear_failed_attempts(&remote_ip, &user_info.username)
                            .await;
                        // The state is `Accepted` here, so this yields the sealed proof.
                        let Some(identity) = AuthorizedIdentity::from_auth_state(&state) else {
                            return Ok(AuthResult::Rejected);
                        };
                        let authorization = if target_name.is_empty() {
                            None
                        } else {
                            let Some(authorization) = authorize_for_target_by_name(
                                self.services.config_provider.as_ref(),
                                &identity,
                                target_name,
                            )
                            .await?
                            else {
                                warn!(
                                    "Target {} not authorized for user {}",
                                    target_name, username
                                );
                                return Ok(AuthResult::Rejected);
                            };
                            Some(authorization)
                        };
                        self.authorized_identity = Some(identity);
                        self._auth_accept(user_info.clone(), authorization).await?;
                        Ok(AuthResult::Accepted { user_info })
                    }
                    x => Ok(x),
                }
            }
            AuthSelector::Ticket { secret } => {
                match authorize_and_spend_ticket(
                    &self.services.db,
                    &self.services.login_protection,
                    secret,
                    Some(remote_ip),
                    crate::PROTOCOL_NAME,
                )
                .await?
                {
                    Some(authorization) => {
                        info!(
                            "Authorized for {} with a ticket",
                            authorization.target().name
                        );
                        let user_info = authorization.user_info().clone();
                        self._auth_accept(user_info.clone(), Some(authorization))
                            .await?;

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
        authorization: Option<TargetAuthorization>,
    ) -> Result<(), WarpgateError> {
        self.user_info = Some(user_info.clone());
        self.server_handle
            .lock()
            .await
            .set_user_info(user_info.clone())
            .await?;

        let Some(authorization) = authorization else {
            self.target = TargetSelection::Menu;
            return Ok(());
        };

        // The authorization already carries the resolved target; all that's left is
        // that it be reachable over SSH.
        let target_name = authorization.target().name.clone();
        let Ok(authorization) = authorization.narrow::<TargetSSHOptions>() else {
            self.target = TargetSelection::NotFound(target_name);
            warn!("Selected target is not an SSH target");
            return Ok(());
        };

        let (target_session_id, approved) = self
            .server_handle
            .lock()
            .await
            .start_target_session(authorization)
            .await?
            .admitted()?;
        self.target_session_id = Some(target_session_id);
        self.target = TargetSelection::Found(approved);
        self.start_recordings_for_pty_channels().await;
        Ok(())
    }

    async fn _channel_close(&mut self, server_channel_id: ServerChannelId) -> Result<()> {
        if self.rc_state == RCState::Disconnected || self.session_handle.is_none() {
            debug!(channel=%server_channel_id.0, "Ignoring close after backend shutdown");
            return Ok(());
        }

        let Ok(channel_id) = self.map_channel(server_channel_id) else {
            debug!(channel=%server_channel_id.0, "Channel already closed");
            return Ok(());
        };
        debug!(channel=%channel_id, "Closing channel");
        self.send_command_and_wait(RCCommand::Channel(channel_id, ChannelOperation::Close))
            .await?;
        self.channels.close(channel_id);
        Ok(())
    }

    fn _channel_eof(&self, server_channel_id: ServerChannelId) -> Result<()> {
        if self.rc_state == RCState::Disconnected || self.session_handle.is_none() {
            debug!(channel=%server_channel_id.0, "Ignoring eof after backend shutdown");
            return Ok(());
        }

        let channel_id = self.map_channel(server_channel_id)?;
        debug!(channel=%channel_id, "EOF");
        let _ = self.send_command(RCCommand::Channel(channel_id, ChannelOperation::Eof));
        Ok(())
    }

    pub async fn _channel_signal(
        &mut self,
        server_channel_id: ServerChannelId,
        signal: Sig,
    ) -> Result<()> {
        if self.rc_state == RCState::Disconnected || self.session_handle.is_none() {
            debug!(channel=%server_channel_id.0, ?signal, "Ignoring signal after backend shutdown");
            return Ok(());
        }

        let channel_id = self.map_channel(server_channel_id)?;
        debug!(channel=%channel_id, ?signal, "Signal");
        self.send_command_and_wait(RCCommand::Channel(
            channel_id,
            ChannelOperation::Signal(signal),
        ))
        .await?;
        Ok(())
    }

    fn send_command(&self, command: RCCommand) -> Result<(), RCCommand> {
        self.rc_tx.send((command, None)).map_err(|e| e.0.0)
    }

    /// Send a command to the target and pump the event loop until its reply
    /// arrives on the oneshot.
    ///
    /// Pumping is not optional: the reply can depend on an event of our own —
    /// the target's unknown-host-key prompt is answered from
    /// [`Self::handle_unknown_host_key`], off this very queue — so merely
    /// draining the queue would deadlock. Past [`MAX_NESTED_COMMAND_WAITS`]
    /// events are buffered instead of dispatched, bounding the stack that the
    /// re-entrant handlers build up.
    async fn send_command_and_wait(&mut self, command: RCCommand) -> Result<(), SshClientError> {
        let (tx, rx) = oneshot::channel();
        let mut cmd = match self.rc_tx.send((command, Some(tx))) {
            Ok(()) => PendingCommand::Waiting(rx),
            Err(_) => PendingCommand::Failed,
        };

        self.command_wait_depth += 1;
        let result = loop {
            tokio::select! {
                result = &mut cmd => {
                    break result
                }
                event = self.get_next_event() => {
                    match event {
                        Some(event) => {
                            if self.command_wait_depth > MAX_NESTED_COMMAND_WAITS {
                                self.pending_events.push_back(event);
                            } else if let Err(error) = self.handle_event(event).await {
                                break Err(error.into());
                            }
                        }
                        None => break Err(SshClientError::MpscError),
                    }
                }
            }
        };
        self.command_wait_depth -= 1;
        result
    }

    pub fn _disconnect(&self) {
        debug!("Client disconnect requested");
        self.request_disconnect();
    }

    fn request_disconnect(&self) {
        debug!("Disconnecting");
        let _ = self.rc_abort_tx.send(());
        if self.rc_state != RCState::NotInitialized && self.rc_state != RCState::Disconnected {
            let _ = self.send_command(RCCommand::Disconnect);
        }
    }

    async fn disconnect_server(&mut self) {
        // Entries stay in place: several callers return into the running event
        // loop, which still needs the channels to record trailing output and to
        // map target events back to the client. Closing twice is harmless —
        // `session_handle` is cleared below, so the second pass sends nothing.
        let channels = self
            .channels
            .values()
            .filter(|channel| channel.is_open())
            .filter_map(Channel::server_id)
            .collect::<Vec<_>>();

        if let Some(handle) = self.session_handle.clone() {
            for ch in channels {
                let _ = self.channel_writer.close(handle.clone(), ch.0);
            }
        }

        // Give queued writes — the closes above, and any error or timeout
        // notice emitted before them — a chance to reach the client. Bounded:
        // a client whose window is full never lets the queue drain, and this
        // runs on the event loop.
        let _ = tokio::time::timeout(DISCONNECT_FLUSH_TIMEOUT, self.channel_writer.flush()).await;

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
            Self::Waiting(rx) => match Pin::new(rx).poll(cx) {
                Poll::Ready(result) => {
                    Poll::Ready(result.unwrap_or(Err(SshClientError::MpscError)))
                }
                Poll::Pending => Poll::Pending,
            },
            Self::Failed => Poll::Ready(Err(SshClientError::MpscError)),
        }
    }
}
