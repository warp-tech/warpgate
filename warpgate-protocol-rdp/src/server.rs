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
//! authentication. Per connection it binds a private loopback socket, spawns the serve
//! helper, and shuttles the raw (TLS) RDP byte stream between the viewer and the helper
//! with [`copy_bidirectional`]. Credentials the viewer submits arrive over the helper's
//! stdout control channel as [`ServerHelperEvent::AuthRequest`]; Warpgate authenticates
//! them with the same [`AuthSelector`] flow used by the native VNC server, connects to
//! the resolved target, and bridges target framebuffer events to the serve helper while
//! recording them — so native RDP records exactly like the in-browser path.

use std::net::{Ipv4Addr, SocketAddr};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use futures::FutureExt;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{ChildStdin, ChildStdout, Command};
use tokio::sync::mpsc::{Sender, UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::time::timeout;
use tokio_stream::StreamExt;
use tracing::{Instrument, debug, error, info, info_span, warn};
use uuid::Uuid;
use warpgate_common::auth::{
    AuthCredential, AuthResult, AuthSelector, AuthStateUserInfo, CredentialKind,
};
use warpgate_common::helpers::net::detect_port_knock;
use warpgate_common::{ListenEndpoint, Secret, Target, TargetOptions, TargetRdpOptions};
use warpgate_core::auth::validate_and_add_credential;
use warpgate_core::login_protection::FailedAttemptInfo;
use warpgate_core::recordings::{DesktopRecorder, DesktopRecordingMetadata};
use warpgate_core::{
    ConfigProvider, DesktopEvent, DesktopInput, DesktopState, Services, SessionStateInit, State,
    WarpgateServerHandle, authorize_ticket, consume_ticket,
};

use crate::session_handle::RdpSessionHandle;
use crate::PROTOCOL_NAME;

/// How long to wait for the serve helper to connect back to our loopback port before
/// giving up (covers a helper that dies on startup, e.g. bad TLS material).
const HELPER_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Desktop size advertised to the viewer before the target connects (the target's real
/// resolution arrives as a `Resize` shortly after).
const DEFAULT_WIDTH: u16 = 1280;
const DEFAULT_HEIGHT: u16 = 800;

/// First stdin line handed to the serve helper. Mirrors its `ServeConfig`.
#[derive(Serialize)]
struct ServeConfig {
    loopback_port: u16,
    cert_pem: String,
    key_pem: String,
    width: u16,
    height: u16,
}

/// Messages Warpgate writes to the serve helper's stdin (after the config line).
/// Mirrors the helper's `ControlIn`.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerHelperInput {
    AuthResponse {
        accept: bool,
    },
    Frame {
        x: u16,
        y: u16,
        width: u16,
        height: u16,
        data: String,
    },
    Resize {
        width: u16,
        height: u16,
    },
    Shutdown,
}

/// Messages Warpgate reads from the serve helper's stdout. Mirrors the helper's
/// `ControlOut`. The helper also reports the viewer's `domain`, but Warpgate resolves
/// the target (and its domain) from the [`AuthSelector`], so that field is ignored.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerHelperEvent {
    AuthRequest { username: String, password: String },
    Pointer { x: u16, y: u16, buttons: u8 },
    Scancode { code: u8, extended: bool, down: bool },
    Key { keysym: u32, down: bool },
    Wheel { x: u16, y: u16, vertical: bool, delta: i16 },
    Error { message: String },
    Disconnected,
}

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
    // state machine. They're connected by a private loopback socket over which we shuttle
    // the raw (TLS) RDP byte stream — Warpgate stays a transparent pipe and never sees
    // plaintext, since TLS is terminated end-to-end between the viewer and the helper.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .context("binding loopback listener for the RDP serve helper")?;
    let loopback_port = listener.local_addr()?.port();

    // Kept in scope until after `spawn` so the Linux memfd stays open across exec.
    let helper = crate::helper::resolve()?;
    let mut child = Command::new(helper.path())
        .arg("serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Kill the helper if this task is cancelled/dropped (tokio doesn't by default).
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("spawning RDP serve helper ({})", helper.path().display()))?;

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

    // First stdin line: the serve config (loopback port + TLS material + initial size).
    let config = ServeConfig {
        loopback_port,
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

    // The helper reads the config, then connects back to our loopback port; bound the
    // wait so a helper that dies on startup doesn't hang the session.
    let (mut loopback, _) = timeout(HELPER_CONNECT_TIMEOUT, listener.accept())
        .await
        .map_err(|_| {
            anyhow!("RDP serve helper did not connect back within {HELPER_CONNECT_TIMEOUT:?}")
        })?
        .context("accepting serve helper loopback connection")?;
    loopback.set_nodelay(true).ok();

    // Run the raw byte relay (viewer ⇄ helper) and the JSON control loop concurrently;
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
            ServerHelperEvent::AuthRequest { username, password } => {
                if backend.is_some() {
                    // Already authenticated; ignore a duplicate request.
                    continue;
                }
                match authenticate(&services, &server_handle, &username, password, remote_address)
                    .await
                {
                    Ok(Some((user_info, target, options))) => {
                        {
                            let handle = server_handle.lock().await;
                            handle.set_user_info(user_info).await?;
                            handle.set_target(&target).await?;
                        }
                        info!(target=%target.name, "Authorized");

                        let session_id = server_handle.lock().await.id();
                        let recorder = start_recorder(&services, &session_id, &target.name)
                            .await
                            .map(Arc::new);

                        let crate::RdpClientHandles {
                            event_rx,
                            input_tx,
                            abort_tx,
                        } = crate::connect(options);
                        let frame_bridge = tokio::spawn(frame_bridge(
                            event_rx,
                            helper_in_tx.clone(),
                            recorder.clone(),
                        ));
                        backend = Some(BackendBridge {
                            input_tx,
                            abort_tx,
                            frame_bridge,
                            recorder,
                        });

                        if helper_in_tx
                            .send(ServerHelperInput::AuthResponse { accept: true })
                            .is_err()
                        {
                            break;
                        }
                    }
                    Ok(None) => {
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
async fn helper_stdin_writer(
    mut stdin: ChildStdin,
    mut rx: UnboundedReceiver<ServerHelperInput>,
) {
    while let Some(msg) = rx.recv().await {
        let Ok(mut line) = serde_json::to_string(&msg) else {
            continue;
        };
        line.push('\n');
        if stdin.write_all(line.as_bytes()).await.is_err() {
            break;
        }
        let _ = stdin.flush().await;
    }
}

/// Start a Desktop recording for this RDP session, mirroring the native VNC / in-browser
/// path. Returns `None` when recording is disabled.
async fn start_recorder(
    services: &Services,
    session_id: &Uuid,
    target_name: &str,
) -> Option<DesktopRecorder> {
    match services
        .recordings
        .lock()
        .await
        .start::<DesktopRecorder, _>(
            session_id,
            None,
            DesktopRecordingMetadata::Desktop {
                // Match the other desktop paths' lowercase tag so all record identically.
                protocol: "rdp".to_owned(),
                target: target_name.to_owned(),
            },
        )
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

/// Authenticate the viewer's submitted credentials.
///
/// RDP collects only a username and password up front (over NLA), so unlike the native
/// VNC server we declare only [`CredentialKind::Password`] and reject any policy that
/// needs an additional interactive factor (TOTP / web approval) — those can't be gathered
/// over the RDP auth exchange. Ticket auth is fully supported.
async fn authenticate(
    services: &Services,
    server_handle: &Arc<tokio::sync::Mutex<WarpgateServerHandle>>,
    selector: &str,
    password: String,
    remote_address: SocketAddr,
) -> Result<Option<(AuthStateUserInfo, Target, TargetRdpOptions)>> {
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
                return Ok(None);
            }
            if services
                .login_protection
                .check_user_locked(&username)
                .await?
                .is_some()
            {
                warn!(username = %username, "RDP auth attempt for locked user");
                return Ok(None);
            }

            let (state_id, state_arc) = services
                .auth_state_store
                .lock()
                .await
                .create(
                    Some(&server_handle.lock().await.id()),
                    &username,
                    PROTOCOL_NAME,
                    &[CredentialKind::Password],
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
                    return Ok(None);
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
                    Ok(Some((user_info, target, options)))
                }
                // RDP can't collect a second factor interactively (see fn doc).
                AuthResult::Need(_) | AuthResult::Rejected => Ok(None),
            }
        }
        AuthSelector::Ticket { secret } => match authorize_ticket(&services.db, &secret).await? {
            Some((ticket, target_model, user_info)) => {
                consume_ticket(&services.db, &ticket.id).await?;
                let (target, options) = find_rdp_target(services, &target_model.name).await?;
                Ok(Some((user_info, target, options)))
            }
            None => Ok(None),
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
