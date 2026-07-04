//! Native RDP server endpoint.
//!
//! Warpgate accepts a raw TCP connection from a standard RDP client (mstsc/FreeRDP)
//! and brokers between two subprocesses of the out-of-workspace RDP helper:
//!
//! * the viewer-facing **serve helper** (`warpgate-rdp-helper serve`) runs the RDP server
//!   state machine and terminates TLS, and
//! * the target-facing **client helper** (`warpgate-rdp-helper connect`, via
//!   [`crate::connect`]) drives the RDP client toward the configured target.
//!
//! Warpgate keeps ownership of the listener, the session/audit lifecycle, and
//! authentication. Per connection it creates a private, unnamed socketpair (the serve
//! helper inherits one end as an fd), spawns the serve helper, and shuttles the raw (TLS)
//! RDP byte stream between the viewer and the helper with [`copy_bidirectional`]. Credentials the viewer submits arrive over the helper's
//! stdout control channel as [`ServerHelperEvent::AuthRequest`]; Warpgate authenticates
//! them with the same [`AuthSelector`] flow used by the native VNC server, connects to
//! the resolved target, and bridges target framebuffer events to the serve helper while
//! recording them — so native RDP records exactly like the in-browser path.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use futures::FutureExt;
use futures::future::BoxFuture;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines, copy_bidirectional};
use tokio::net::{TcpStream, UnixStream};
use tokio::process::{ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;
use tokio::sync::mpsc::{Sender, UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio_stream::StreamExt;
use tracing::{Instrument, debug, error, info, info_span, warn};
use uuid::Uuid;
use warpgate_common::auth::{
    AuthCredential, AuthResult, AuthSelector, AuthState, AuthStateUserInfo, CredentialKind,
};
use warpgate_common::helpers::net::detect_port_knock;
use warpgate_common::helpers::otp::OTP_DIGITS;
use warpgate_common::{ListenEndpoint, Secret, Target, TargetOptions, TargetRdpOptions};
use warpgate_common_http::ext::construct_external_url;
use warpgate_core::auth::validate_and_add_credential;
use warpgate_core::login_protection::FailedAttemptInfo;
use warpgate_core::recordings::{DesktopRecorder, DesktopRecordingMetadata};
use warpgate_core::{
    ConfigProvider, DesktopEvent, DesktopInput, DesktopState, Services, SessionStateInit, State,
    WarpgateServerHandle, authorize_ticket, consume_ticket,
};
use warpgate_protocol_vnc_ui as ui;
use warpgate_rdp_ipc::server::{
    Event as ServerHelperEvent, Input as ServerHelperInput, ServeConfig,
};

use crate::PROTOCOL_NAME;
use crate::session_handle::RdpSessionHandle;

/// The fd number at which the serve helper receives its end of the RDP transport
/// socketpair (`dup2`'d into place by `pre_exec`, then passed to the helper as a CLI arg).
const HELPER_STREAM_FD: i32 = 3;
/// Desktop size advertised to the viewer before the target connects (the target's real
/// resolution arrives as a `Resize` shortly after).
const DEFAULT_WIDTH: u16 = 1280;
const DEFAULT_HEIGHT: u16 = 800;

/// Handles to the connected target-side RDP client, kept once authentication succeeds.
struct BackendBridge {
    input_tx: Sender<DesktopInput>,
    abort_tx: UnboundedSender<()>,
    frame_bridge: tokio::task::JoinHandle<()>,
    /// Shared with `frame_bridge`; used to record viewer input alongside the
    /// framebuffer. `None` when recording is disabled.
    recorder: Option<Arc<DesktopRecorder>>,
}

impl BackendBridge {
    /// Stop the target client and its frame bridge.
    fn shutdown(self) {
        let _ = self.abort_tx.send(());
        self.frame_bridge.abort();
    }
}

pub async fn bind_server(
    services: Services,
    address: ListenEndpoint,
    // The serve helper terminates TLS itself (it has its own rustls with a different
    // crypto provider), so we hand it the raw PEM rather than a built acceptor.
    cert_pem: String,
    key_pem: String,
) -> Result<BoxFuture<'static, Result<()>>> {
    let mut listener = address.tcp_accept_stream().await?;

    Ok(async move {
        while let Some(stream) = listener.next().await {
            let Ok(remote_address) = stream.peer_addr() else {
                continue;
            };
            let _ = stream.set_nodelay(true);
            if detect_port_knock(&stream).await {
                continue;
            }

            let services = services.clone();
            let cert_pem = cert_pem.clone();
            let key_pem = key_pem.clone();
            tokio::spawn(async move {
                let (session_handle, mut abort_rx) = RdpSessionHandle::new();

                let server_handle = match State::register_session(
                    &services.state,
                    &PROTOCOL_NAME,
                    SessionStateInit {
                        remote_address: Some(remote_address),
                        handle: Box::new(session_handle),
                    },
                )
                .await
                {
                    Ok(h) => h,
                    Err(error) => {
                        error!(%error, "Failed to register session");
                        return;
                    }
                };

                let span = info_span!("RDP", session=%server_handle.lock().await.id());

                tokio::select! {
                    result = handle_connection(
                        services,
                        server_handle.clone(),
                        stream,
                        remote_address,
                        cert_pem,
                        key_pem,
                    ).instrument(span) => match result {
                        Ok(()) => info!("Session ended"),
                        Err(error) => error!(%error, "Session failed"),
                    },
                    _ = abort_rx.recv() => {
                        warn!("Session aborted by admin");
                    }
                }
            });
        }

        Ok(())
    }
    .boxed())
}

async fn handle_connection(
    services: Services,
    server_handle: Arc<tokio::sync::Mutex<WarpgateServerHandle>>,
    stream: TcpStream,
    remote_address: SocketAddr,
    cert_pem: String,
    key_pem: String,
) -> Result<()> {
    let mut viewer = {
        let guard = server_handle.lock().await;
        guard.wrap_stream(stream).await?
    };

    // Warpgate owns the viewer socket + session; the serve helper runs the RDP server
    // state machine. They're connected by a private, unnamed socketpair — the helper
    // inherits its end as fd HELPER_STREAM_FD, so there's no loopback port for another
    // local process to connect to or race. Warpgate stays a transparent pipe of the raw
    // (TLS) RDP bytes and never sees plaintext: TLS is terminated end-to-end between the
    // viewer and the helper.
    let (warpgate_end, helper_end) =
        StdUnixStream::pair().context("creating the RDP serve helper socketpair")?;
    warpgate_end
        .set_nonblocking(true)
        .context("making the RDP transport non-blocking")?;
    let mut loopback =
        UnixStream::from_std(warpgate_end).context("wrapping the RDP transport")?;
    let helper_fd = helper_end.as_raw_fd();

    // Kept in scope until after `spawn` so the Linux memfd stays open across exec.
    let helper = crate::helper::resolve()?;
    let mut command = Command::new(helper.path());
    command
        .arg("serve")
        .arg(HELPER_STREAM_FD.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Kill the helper if this task is cancelled/dropped (tokio doesn't by default).
        .kill_on_drop(true);
    // Hand the helper its end of the socketpair as fd HELPER_STREAM_FD. `dup2` produces a
    // fresh, non-CLOEXEC fd *in this child only*, while `helper_end` keeps CLOEXEC in the
    // parent — so concurrent per-connection spawns can't inherit each other's transport.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(helper_fd, HELPER_STREAM_FD) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("spawning RDP serve helper ({})", helper.path().display()))?;
    // The child now holds its own copy of the transport; drop ours so the socket fully
    // closes (and the relay sees EOF) once the helper exits.
    drop(helper_end);

    let mut child_stdin = child.stdin.take().context("serve helper stdin")?;
    let child_stdout = child.stdout.take().context("serve helper stdout")?;

    // Surface helper diagnostics (panics, errors) to the log instead of discarding them.
    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                debug!(helper = %line, "RDP serve helper stderr");
            }
        });
    }

    // First stdin line: the serve config (TLS material + initial size).
    let config = ServeConfig {
        cert_pem,
        key_pem,
        width: DEFAULT_WIDTH,
        height: DEFAULT_HEIGHT,
    };
    let mut config_line = serde_json::to_string(&config)?;
    config_line.push('\n');
    child_stdin.write_all(config_line.as_bytes()).await?;
    child_stdin.flush().await?;

    // All subsequent helper stdin writes are funnelled through one task.
    let (helper_in_tx, helper_in_rx) = unbounded_channel::<ServerHelperInput>();
    let stdin_task = tokio::spawn(helper_stdin_writer(child_stdin, helper_in_rx));

    // The socketpair is already connected — no connect-back to wait for. Run the raw byte
    // relay (viewer ⇄ helper) and the JSON control loop concurrently;
    // whichever ends first tears the session down.
    tokio::select! {
        result = control_loop(services, server_handle, remote_address, child_stdout, helper_in_tx) => {
            result?;
        }
        result = copy_bidirectional(&mut viewer, &mut loopback) => {
            match result {
                Ok((to_helper, to_viewer)) => {
                    debug!(to_helper, to_viewer, "RDP byte relay ended");
                }
                Err(error) => debug!(%error, "RDP byte relay error"),
            }
        }
    }

    stdin_task.abort();
    let _ = child.kill().await;
    Ok(())
}

/// Read the serve helper's control channel: authenticate the viewer, connect to the
/// target on success, and forward viewer input to the target client.
async fn control_loop(
    services: Services,
    server_handle: Arc<tokio::sync::Mutex<WarpgateServerHandle>>,
    remote_address: SocketAddr,
    stdout: ChildStdout,
    helper_in_tx: UnboundedSender<ServerHelperInput>,
) -> Result<()> {
    let mut lines = BufReader::new(stdout).lines();
    let mut backend: Option<BackendBridge> = None;

    while let Some(line) = lines
        .next_line()
        .await
        .context("reading serve helper output")?
    {
        let Ok(event) = serde_json::from_str::<ServerHelperEvent>(line.trim()) else {
            continue;
        };

        let input = match event {
            ServerHelperEvent::AuthRequest {
                username, password, ..
            } => {
                if backend.is_some() {
                    // Already authenticated; ignore a duplicate request.
                    continue;
                }
                match authenticate(
                    &services,
                    &server_handle,
                    &username,
                    password,
                    remote_address,
                )
                .await
                {
                    Ok(AuthOutcome::Authorized(user_info, target, options)) => {
                        backend = Some(
                            connect_backend(
                                &services,
                                &server_handle,
                                &helper_in_tx,
                                user_info,
                                target,
                                options,
                            )
                            .await?,
                        );
                        if helper_in_tx
                            .send(ServerHelperInput::AuthResponse { accept: true })
                            .is_err()
                        {
                            break;
                        }
                    }
                    Ok(AuthOutcome::NeedsInteractive(interactive)) => {
                        // Accept the NLA so the RDP session starts, then collect the second
                        // factor (TOTP / web approval) on a Warpgate-rendered holding screen
                        // before connecting to the target.
                        if helper_in_tx
                            .send(ServerHelperInput::AuthResponse { accept: true })
                            .is_err()
                        {
                            break;
                        }
                        match run_hold_screen(&services, &interactive, &mut lines, &helper_in_tx)
                            .await
                        {
                            Ok(Some(user_info)) => {
                                match finalize_user_auth(
                                    &services,
                                    &interactive.username,
                                    &interactive.target_name,
                                )
                                .await
                                {
                                    Ok((target, options)) => {
                                        backend = Some(
                                            connect_backend(
                                                &services,
                                                &server_handle,
                                                &helper_in_tx,
                                                user_info,
                                                target,
                                                options,
                                            )
                                            .await?,
                                        );
                                    }
                                    Err(error) => {
                                        warn!(%error, "Authorization failed after second factor");
                                        let _ = helper_in_tx.send(ServerHelperInput::Shutdown);
                                        break;
                                    }
                                }
                            }
                            Ok(None) => {
                                warn!("Interactive authentication failed");
                                let _ = helper_in_tx.send(ServerHelperInput::Shutdown);
                                break;
                            }
                            Err(error) => {
                                warn!(%error, "Holding-screen error");
                                let _ = helper_in_tx.send(ServerHelperInput::Shutdown);
                                break;
                            }
                        }
                    }
                    Ok(AuthOutcome::Failed) => {
                        warn!("Authentication failed");
                        let _ =
                            helper_in_tx.send(ServerHelperInput::AuthResponse { accept: false });
                    }
                    Err(error) => {
                        warn!(%error, "Authentication error");
                        let _ =
                            helper_in_tx.send(ServerHelperInput::AuthResponse { accept: false });
                    }
                }
                continue;
            }
            ServerHelperEvent::Error { message } => {
                warn!(%message, "RDP serve helper reported an error");
                continue;
            }
            ServerHelperEvent::Disconnected => break,

            // Viewer input: record it for audit (like native VNC) then forward to the
            // target. `break` once the target client is gone (send fails).
            ServerHelperEvent::Pointer { x, y, buttons } => DesktopInput::Pointer { x, y, buttons },
            ServerHelperEvent::Scancode {
                code,
                extended,
                down,
            } => DesktopInput::Scancode {
                code,
                extended,
                down,
            },
            ServerHelperEvent::Key { keysym, down } => DesktopInput::Key { keysym, down },
            ServerHelperEvent::Wheel {
                x,
                y,
                vertical,
                delta,
            } => DesktopInput::Wheel {
                x,
                y,
                vertical,
                delta,
            },
        };

        // Reached only for the viewer-input variants above.
        let Some(backend) = &backend else {
            continue;
        };
        if let Some(recorder) = &backend.recorder
            && let Err(error) = recorder.write_input(&input).await
        {
            warn!(%error, "Failed to record RDP viewer input");
        }
        if backend.input_tx.send(input).await.is_err() {
            break;
        }
    }

    if let Some(backend) = backend {
        backend.shutdown();
    }
    Ok(())
}

/// Bridge target-side desktop events to the serve helper, recording each. The recorder
/// is shared with `control_loop` (which records viewer input); the recording finalises
/// once both drop their handle.
async fn frame_bridge(
    mut event_rx: tokio::sync::mpsc::Receiver<DesktopEvent>,
    helper_in_tx: UnboundedSender<ServerHelperInput>,
    recorder: Option<Arc<DesktopRecorder>>,
) {
    while let Some(event) = event_rx.recv().await {
        if let Some(recorder) = &recorder
            && let Err(error) = recorder.write_event(&event).await
        {
            warn!(%error, "Failed to record RDP desktop event");
        }

        let message = match event {
            DesktopEvent::Resize { width, height } => ServerHelperInput::Resize { width, height },
            DesktopEvent::RawImage { rect, data } => ServerHelperInput::Frame {
                x: rect.x,
                y: rect.y,
                width: rect.width,
                height: rect.height,
                data: STANDARD.encode(&data),
            },
            DesktopEvent::State(DesktopState::Disconnected) => {
                let _ = helper_in_tx.send(ServerHelperInput::Shutdown);
                break;
            }
            DesktopEvent::Error(message) => {
                warn!(%message, "RDP target reported an error");
                continue;
            }
            // The client helper only emits Connecting/Connected/Resize/RawImage/Error/
            // Disconnected; the remaining framebuffer variants never occur on this path.
            _ => continue,
        };

        if helper_in_tx.send(message).is_err() {
            break;
        }
    }
}

/// Funnel queued [`ServerHelperInput`] messages to the serve helper's stdin as
/// line-delimited JSON.
/// How many framebuffer updates may be queued toward the serve helper before we start
/// shedding the oldest. Serializing a `Frame` means JSON-encoding a ~1 MB base64 string;
/// if the viewer/helper falls behind, an unbounded queue would pin a core on that and lag
/// the screen far behind live. Small on purpose so we deliver the live edge, not a backlog.
const MAX_PENDING_HELPER_FRAMES: usize = 8;

async fn helper_stdin_writer(mut stdin: ChildStdin, mut rx: UnboundedReceiver<ServerHelperInput>) {
    let mut batch: std::collections::VecDeque<ServerHelperInput> = std::collections::VecDeque::new();
    loop {
        // Block for at least one message, then drain everything else already queued so we
        // can shed staleness across the whole burst before doing any expensive work.
        match rx.recv().await {
            Some(msg) => batch.push_back(msg),
            None => return,
        }
        while let Ok(msg) = rx.try_recv() {
            batch.push_back(msg);
        }

        // Drop the oldest framebuffer updates beyond the cap; never drop control messages
        // (auth verdicts / resize / shutdown), whose loss would desync the viewer.
        let is_frame = |m: &ServerHelperInput| matches!(m, ServerHelperInput::Frame { .. });
        let mut frames = batch.iter().filter(|m| is_frame(m)).count();
        while frames > MAX_PENDING_HELPER_FRAMES {
            if let Some(pos) = batch.iter().position(is_frame) {
                batch.remove(pos);
                frames -= 1;
            } else {
                break;
            }
        }

        for msg in batch.drain(..) {
            let Ok(mut line) = serde_json::to_string(&msg) else {
                continue;
            };
            line.push('\n');
            if stdin.write_all(line.as_bytes()).await.is_err() {
                return;
            }
        }
        let _ = stdin.flush().await;
    }
}

/// Start a Desktop recording for this RDP session, mirroring the native VNC / in-browser
/// path. Returns `None` when recording is disabled.
async fn start_recorder(services: &Services, session_id: &Uuid) -> Option<DesktopRecorder> {
    match services
        .recordings
        .lock()
        .await
        .start::<DesktopRecorder, _>(session_id, None, DesktopRecordingMetadata)
        .await
    {
        Ok(recorder) => Some(recorder),
        Err(warpgate_core::recordings::Error::Disabled) => None,
        Err(error) => {
            warn!(%error, "Failed to start RDP session recording");
            None
        }
    }
}

/// Result of validating the viewer's up-front (NLA) credentials.
enum AuthOutcome {
    /// Fully authenticated (password-only policy, or ticket auth).
    Authorized(AuthStateUserInfo, Target, TargetRdpOptions),
    /// Password accepted, but the policy needs an interactive second factor
    /// (TOTP / web approval) — collected on the holding screen ([`run_hold_screen`]).
    NeedsInteractive(InteractiveAuth),
    /// Rejected, invalid, blocked, or a factor we can't collect over RDP.
    Failed,
}

/// A partially-authenticated session awaiting its interactive second factor.
struct InteractiveAuth {
    state_id: Uuid,
    username: String,
    target_name: String,
    remote_ip: IpAddr,
}

/// Authenticate the viewer's submitted credentials.
///
/// RDP collects only a username and password up front (over NLA). A password-only policy
/// (or a ticket) authorises immediately; a policy that additionally needs TOTP or web
/// approval returns [`AuthOutcome::NeedsInteractive`], and the caller gathers that factor
/// on a holding screen after provisionally accepting the NLA.
async fn authenticate(
    services: &Services,
    server_handle: &Arc<Mutex<WarpgateServerHandle>>,
    selector: &str,
    password: String,
    remote_address: SocketAddr,
) -> Result<AuthOutcome> {
    let selector: AuthSelector = selector.into();

    match selector {
        AuthSelector::User {
            username,
            target_name,
        } => {
            let remote_ip = remote_address.ip();

            // Brute-force protection: reject blocked IPs / locked users before
            // evaluating credentials. Fail closed (propagate lookup errors).
            if services
                .login_protection
                .check_ip_blocked(&remote_ip)
                .await?
                .is_some()
            {
                warn!(ip = %remote_ip, "RDP auth attempt from blocked IP");
                return Ok(AuthOutcome::Failed);
            }
            if services
                .login_protection
                .check_user_locked(&username)
                .await?
                .is_some()
            {
                warn!(username = %username, "RDP auth attempt for locked user");
                return Ok(AuthOutcome::Failed);
            }

            let (state_id, state_arc) = services
                .auth_state_store
                .lock()
                .await
                .create(
                    Some(&server_handle.lock().await.id()),
                    &username,
                    PROTOCOL_NAME,
                    &[
                        CredentialKind::Password,
                        CredentialKind::Totp,
                        CredentialKind::WebUserApproval,
                    ],
                    Some(remote_address.ip()),
                    Some("password"),
                )
                .await?;

            {
                let credential = AuthCredential::Password(Secret::new(password));
                let mut state = state_arc.lock().await;
                let credential_valid = validate_and_add_credential(
                    &mut state,
                    &credential,
                    &mut *services.config_provider.lock().await,
                )
                .await?;
                if !credential_valid {
                    let _ = services
                        .login_protection
                        .record_failed_attempt(FailedAttemptInfo {
                            username: username.clone(),
                            remote_ip,
                            protocol: "rdp".to_string(),
                            credential_type: "password".to_string(),
                        })
                        .await;
                    return Ok(AuthOutcome::Failed);
                }
            }

            match state_arc.lock().await.verify() {
                AuthResult::Accepted { user_info } => {
                    let _ = services
                        .login_protection
                        .clear_failed_attempts(&remote_ip, &user_info.username)
                        .await;
                    services
                        .auth_state_store
                        .lock()
                        .await
                        .complete(&state_id)
                        .await;
                    let (target, options) =
                        finalize_user_auth(services, &user_info.username, &target_name).await?;
                    Ok(AuthOutcome::Authorized(user_info, target, options))
                }
                AuthResult::Need(kinds)
                    if kinds.contains(&CredentialKind::Totp)
                        || kinds.contains(&CredentialKind::WebUserApproval) =>
                {
                    Ok(AuthOutcome::NeedsInteractive(InteractiveAuth {
                        state_id,
                        username,
                        target_name,
                        remote_ip,
                    }))
                }
                // A required factor we can't collect on the holding screen.
                AuthResult::Need(_) | AuthResult::Rejected => Ok(AuthOutcome::Failed),
            }
        }
        AuthSelector::Ticket { secret } => match authorize_ticket(&services.db, &secret).await? {
            Some((ticket, target_model, user_info)) => {
                consume_ticket(&services.db, &ticket.id).await?;
                let (target, options) = find_rdp_target(services, &target_model.name).await?;
                Ok(AuthOutcome::Authorized(user_info, target, options))
            }
            None => Ok(AuthOutcome::Failed),
        },
    }
}

async fn finalize_user_auth(
    services: &Services,
    username: &str,
    target_name: &str,
) -> Result<(Target, TargetRdpOptions)> {
    let authorized = services
        .config_provider
        .lock()
        .await
        .authorize_target(username, target_name)
        .await?;
    if !authorized {
        bail!("Target {target_name} not authorized for {username}");
    }
    find_rdp_target(services, target_name).await
}

async fn find_rdp_target(
    services: &Services,
    target_name: &str,
) -> Result<(Target, TargetRdpOptions)> {
    let Some(target) = services
        .config_provider
        .lock()
        .await
        .get_target_by_name(target_name)
        .await?
    else {
        bail!("Target {target_name} not found");
    };
    let TargetOptions::Rdp(ref options) = target.options else {
        bail!("Target {target_name} is not an RDP target");
    };
    Ok((target.clone(), options.clone()))
}

/// Connect to the target and start bridging its framebuffer, once auth is complete.
async fn connect_backend(
    services: &Services,
    server_handle: &Arc<Mutex<WarpgateServerHandle>>,
    helper_in_tx: &UnboundedSender<ServerHelperInput>,
    user_info: AuthStateUserInfo,
    target: Target,
    options: TargetRdpOptions,
) -> Result<BackendBridge> {
    {
        let handle = server_handle.lock().await;
        handle.set_user_info(user_info).await?;
        handle.set_target(&target).await?;
    }
    info!(target=%target.name, "Authorized");

    let session_id = server_handle.lock().await.id();
    let recorder = start_recorder(services, &session_id).await.map(Arc::new);

    let crate::RdpClientHandles {
        event_rx,
        input_tx,
        abort_tx,
    } = crate::connect(options);
    let frame_bridge = tokio::spawn(frame_bridge(event_rx, helper_in_tx.clone(), recorder.clone()));
    Ok(BackendBridge {
        input_tx,
        abort_tx,
        frame_bridge,
        recorder,
    })
}

/// How often the holding screen repaints (spinner animation cadence).
const HOLD_RENDER_INTERVAL: Duration = Duration::from_millis(200);
/// Max wrong one-time passwords entered on the holding screen before giving up.
const MAX_OTP_ATTEMPTS: usize = 3;

/// A single OTP keypress on the holding screen.
enum OtpAction {
    Digit(char),
    Backspace,
    Submit,
}

/// Render a holding screen to the viewer and collect the interactive second factor — a
/// TOTP typed on the viewer's keyboard, or an out-of-band web approval — until the auth
/// state is fully accepted. Returns the authenticated user on success, `None` on failure
/// or viewer disconnect. Input events are read from the same serve-helper channel as the
/// main control loop, so it hands us `&mut lines` for the duration.
async fn run_hold_screen(
    services: &Services,
    interactive: &InteractiveAuth,
    lines: &mut Lines<BufReader<ChildStdout>>,
    helper_in_tx: &UnboundedSender<ServerHelperInput>,
) -> Result<Option<AuthStateUserInfo>> {
    let state = services
        .auth_state_store
        .lock()
        .await
        .get(&interactive.state_id)
        .context("auth state expired")?;
    let mut approval = services
        .auth_state_store
        .lock()
        .await
        .subscribe(interactive.state_id);

    // Size the viewer to the UI canvas; the target's real size follows once it connects.
    let _ = helper_in_tx.send(ServerHelperInput::Resize {
        width: ui::SCREEN_W,
        height: ui::SCREEN_H,
    });

    let mut otp = String::new();
    let mut otp_failures = 0usize;
    let mut tick = 0u64;
    let mut ticker = tokio::time::interval(HOLD_RENDER_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        let need = match state.lock().await.verify() {
            AuthResult::Accepted { user_info } => {
                let _ = services
                    .login_protection
                    .clear_failed_attempts(&interactive.remote_ip, &user_info.username)
                    .await;
                services
                    .auth_state_store
                    .lock()
                    .await
                    .complete(&interactive.state_id)
                    .await;
                return Ok(Some(user_info));
            }
            AuthResult::Rejected => return Ok(None),
            AuthResult::Need(need) => need,
        };

        let Some(prompt) = build_prompt(services, &state, &need, &otp).await else {
            warn!(
                "RDP auth policy requires a factor that can't be collected on the holding screen"
            );
            return Ok(None);
        };
        let awaiting_web = matches!(prompt, ui::AuthPrompt::WebApproval { .. });

        render_hold_frame(helper_in_tx, tick, &prompt)?;

        tokio::select! {
            // Browser approval landed (or the signal lagged/closed); re-verify on the next loop.
            _ = approval.recv(), if awaiting_web => {}
            line = lines.next_line() => {
                let Some(line) = line.context("reading serve helper output")? else {
                    return Ok(None);
                };
                let action = match serde_json::from_str::<ServerHelperEvent>(line.trim()) {
                    Ok(ServerHelperEvent::Disconnected) => return Ok(None),
                    Ok(ServerHelperEvent::Scancode { code, down, .. }) if down => {
                        scancode_otp_action(code)
                    }
                    Ok(ServerHelperEvent::Key { keysym, down }) if down => key_otp_action(keysym),
                    _ => None,
                };
                if !awaiting_web
                    && let Some(action) = action
                    && apply_otp(action, &mut otp, &mut otp_failures, services, &state, interactive)
                        .await?
                {
                    warn!("too many incorrect one-time passwords");
                    return Ok(None);
                }
            }
            _ = ticker.tick() => tick = tick.wrapping_add(1),
        }
    }
}

/// Pick the prompt to show for the credentials still needed. Mirrors the native VNC flow:
/// TOTP takes precedence over web approval when a policy allows either.
async fn build_prompt(
    services: &Services,
    state: &Arc<Mutex<AuthState>>,
    need: &HashSet<CredentialKind>,
    otp: &str,
) -> Option<ui::AuthPrompt> {
    if need.contains(&CredentialKind::Totp) {
        Some(ui::AuthPrompt::Otp {
            entered: otp.to_owned(),
        })
    } else if need.contains(&CredentialKind::WebUserApproval) {
        Some(ui::AuthPrompt::WebApproval {
            url: web_approval_url(services, state).await,
            security_key: state.lock().await.identification_string().to_owned(),
        })
    } else {
        None
    }
}

async fn web_approval_url(services: &Services, state: &Arc<Mutex<AuthState>>) -> Option<String> {
    let external_url = {
        let config = services.config.lock().await;
        construct_external_url(None, &config, None)
            .await
            .inspect_err(|error| warn!(%error, "Failed to construct external URL"))
            .ok()?
    };
    let url = state.lock().await.construct_web_approval_url(external_url);
    Some(url.to_string())
}

/// Apply one OTP keypress. Returns `Ok(true)` when too many wrong OTPs have been entered
/// and the session should be abandoned.
async fn apply_otp(
    action: OtpAction,
    otp: &mut String,
    otp_failures: &mut usize,
    services: &Services,
    state: &Arc<Mutex<AuthState>>,
    interactive: &InteractiveAuth,
) -> Result<bool> {
    let submit = match action {
        OtpAction::Digit(c) => {
            // OTP chars are always ASCII digits, so byte length == char count.
            if otp.len() < OTP_DIGITS {
                otp.push(c);
            }
            otp.len() >= OTP_DIGITS
        }
        OtpAction::Backspace => {
            otp.pop();
            false
        }
        OtpAction::Submit => !otp.is_empty(),
    };
    if !submit {
        return Ok(false);
    }

    let credential = AuthCredential::Otp(Secret::new(std::mem::take(otp)));
    // Route through the shared helper so a bad OTP emits the same audit event as SSH/etc.
    let valid = validate_and_add_credential(
        &mut *state.lock().await,
        &credential,
        &mut *services.config_provider.lock().await,
    )
    .await
    .unwrap_or(false);

    if !valid {
        *otp_failures += 1;
        let _ = services
            .login_protection
            .record_failed_attempt(FailedAttemptInfo {
                username: interactive.username.clone(),
                remote_ip: interactive.remote_ip,
                protocol: "rdp".to_string(),
                credential_type: "otp".to_string(),
            })
            .await;
        if *otp_failures >= MAX_OTP_ATTEMPTS {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Paint the current holding-screen prompt to the viewer as a full BGRA frame.
fn render_hold_frame(
    helper_in_tx: &UnboundedSender<ServerHelperInput>,
    tick: u64,
    prompt: &ui::AuthPrompt,
) -> Result<()> {
    // The UI renders RGB888 (the VNC screen); convert to the BGRA the serve helper expects.
    let rgb = ui::render_authentication(tick, prompt).unwrap_or_default();
    let mut bgra = Vec::with_capacity(rgb.len() / 3 * 4);
    for px in rgb.chunks_exact(3) {
        if let Some(&[r, g, b]) = px.first_chunk::<3>() {
            bgra.extend_from_slice(&[b, g, r, 255]);
        }
    }
    if helper_in_tx
        .send(ServerHelperInput::Frame {
            x: 0,
            y: 0,
            width: ui::SCREEN_W,
            height: ui::SCREEN_H,
            data: STANDARD.encode(&bgra),
        })
        .is_err()
    {
        bail!("serve helper channel closed");
    }
    Ok(())
}

/// Map a PC/AT set-1 scancode (what mstsc/FreeRDP send) to an OTP action.
fn scancode_otp_action(code: u8) -> Option<OtpAction> {
    Some(match code {
        0x02..=0x0a => OtpAction::Digit(char::from(b'1' + (code - 0x02))), // top row 1..9
        0x0b => OtpAction::Digit('0'),
        0x52 => OtpAction::Digit('0'), // keypad 0
        0x4f => OtpAction::Digit('1'),
        0x50 => OtpAction::Digit('2'),
        0x51 => OtpAction::Digit('3'),
        0x4b => OtpAction::Digit('4'),
        0x4c => OtpAction::Digit('5'),
        0x4d => OtpAction::Digit('6'),
        0x47 => OtpAction::Digit('7'),
        0x48 => OtpAction::Digit('8'),
        0x49 => OtpAction::Digit('9'),
        0x0e => OtpAction::Backspace,
        0x1c => OtpAction::Submit, // Enter (main + keypad)
        _ => return None,
    })
}

/// Map a Unicode keypress (viewers that send `Key` instead of scancodes) to an OTP action.
fn key_otp_action(keysym: u32) -> Option<OtpAction> {
    Some(match keysym {
        0x30..=0x39 => OtpAction::Digit(char::from(u8::try_from(keysym).ok()?)), // '0'..'9'
        0x08 => OtpAction::Backspace,
        0x0d | 0x0a => OtpAction::Submit, // CR / LF
        _ => return None,
    })
}

#[cfg(test)]
mod otp_input_tests {
    use super::{OtpAction, key_otp_action, scancode_otp_action};

    fn digit(action: Option<OtpAction>) -> Option<char> {
        match action {
            Some(OtpAction::Digit(c)) => Some(c),
            _ => None,
        }
    }

    #[test]
    fn scancode_number_row() {
        // 0x02..=0x0a is the '1'..'9' row (computed, so guard the ends), 0x0b is '0'.
        assert_eq!(digit(scancode_otp_action(0x02)), Some('1'));
        assert_eq!(digit(scancode_otp_action(0x0a)), Some('9'));
        assert_eq!(digit(scancode_otp_action(0x0b)), Some('0'));
    }

    #[test]
    fn scancode_keypad() {
        for (code, expected) in [
            (0x52u8, '0'),
            (0x4f, '1'),
            (0x50, '2'),
            (0x51, '3'),
            (0x4b, '4'),
            (0x4c, '5'),
            (0x4d, '6'),
            (0x47, '7'),
            (0x48, '8'),
            (0x49, '9'),
        ] {
            assert_eq!(digit(scancode_otp_action(code)), Some(expected), "scancode {code:#x}");
        }
    }

    #[test]
    fn scancode_control_and_unmapped() {
        assert!(matches!(scancode_otp_action(0x0e), Some(OtpAction::Backspace)));
        assert!(matches!(scancode_otp_action(0x1c), Some(OtpAction::Submit)));
        assert!(scancode_otp_action(0x3b).is_none()); // F1 — not an OTP key
        assert!(scancode_otp_action(0x00).is_none());
    }

    #[test]
    fn keysym_digits_control_and_unmapped() {
        for d in 0..=9u8 {
            let c = char::from(b'0' + d);
            assert_eq!(digit(key_otp_action(u32::from(c))), Some(c));
        }
        assert!(matches!(key_otp_action(0x08), Some(OtpAction::Backspace)));
        assert!(matches!(key_otp_action(0x0d), Some(OtpAction::Submit)));
        assert!(matches!(key_otp_action(0x0a), Some(OtpAction::Submit)));
        assert!(key_otp_action(u32::from('A')).is_none());
        assert!(key_otp_action(u32::from(' ')).is_none());
    }
}
