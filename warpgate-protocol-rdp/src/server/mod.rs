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

use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::Arc;

use anyhow::{Context, Result};
use futures::future::BoxFuture;
use futures::{FutureExt, SinkExt};
use tokio::io::{AsyncBufReadExt, BufReader, copy_bidirectional};
use tokio::net::TcpStream;
use tokio::process::{ChildStdin, ChildStdout, Command};
use tokio::sync::mpsc::{Sender, UnboundedSender, unbounded_channel};
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use tracing::{Instrument, debug, error, info, info_span, warn};
use warpgate_common::helpers::net::detect_port_knock;
use warpgate_common::{ListenEndpoint, Target, TargetOptions, TargetRdpOptions};
use warpgate_core::recordings::DesktopRecorder;
use warpgate_core::{DesktopInput, Services, SessionStateInit, State, WarpgateServerHandle};
use warpgate_rdp_ipc::server::{
    Event as ServerHelperEvent, Input as ServerHelperInput, ServeConfig,
};

use crate::PROTOCOL_NAME;
use crate::session_handle::RdpSessionHandle;

mod bridge;
mod hold_screen;
mod transport;

use bridge::{connect_backend, helper_stdin_writer};
use hold_screen::run_hold_screen;
use warpgate_desktop_auth::{
    DesktopAuthOutcome, DesktopProtocol, authenticate, finalize_user_auth,
};

/// The fd number at which the serve helper receives its end of the RDP transport
/// socketpair (`dup2`'d into place by `pre_exec`, then passed to the helper as a CLI arg).
const HELPER_STREAM_FD: i32 = 3;
/// Desktop size advertised to the viewer before the target connects (the target's real
/// resolution arrives as a `Resize` shortly after).
const DEFAULT_WIDTH: u16 = 1280;
const DEFAULT_HEIGHT: u16 = 800;

/// Length-delimited frame reader/writer over the serve helper's stdio. Frames can be a
/// full-screen BGRA rect, so the size cap is raised past the codec's 8 MB default.
type HelperReader = FramedRead<ChildStdout, LengthDelimitedCodec>;
type HelperWriter = FramedWrite<ChildStdin, LengthDelimitedCodec>;

fn helper_codec() -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .max_frame_length(warpgate_rdp_ipc::MAX_FRAME_LEN)
        .new_codec()
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
    proxy_protocol: bool,
    // The serve helper terminates TLS itself (it has its own rustls with a different
    // crypto provider), so we hand it the raw PEM rather than a built acceptor.
    cert_pem: String,
    key_pem: String,
) -> Result<BoxFuture<'static, Result<()>>> {
    let mut listener = address.tcp_accept_stream().await?;

    Ok(async move {
        while let Some(mut stream) = listener.next().await {
            let _ = stream.set_nodelay(true);
            if detect_port_knock(&stream).await {
                continue;
            }
            let remote_address = match warpgate_common::helpers::proxy_protocol::remote_address(
                &mut stream,
                proxy_protocol,
            )
            .await
            {
                Ok(remote_address) => remote_address,
                Err(error) => {
                    warn!(%error, "Failed to read PROXY protocol header");
                    continue;
                }
            };

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

    // Warpgate owns the viewer socket + session; the serve helper runs the RDP server state
    // machine. They're connected by a private, unnamed socketpair (see [`transport`]) — the
    // helper inherits its end as fd HELPER_STREAM_FD, so there's no loopback port for another
    // local process to connect to or race. Warpgate stays a transparent pipe of the raw (TLS)
    // RDP bytes and never sees plaintext: TLS is terminated end-to-end between the viewer and
    // the helper.
    //
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
    let (mut loopback, mut child) = transport::spawn_with_transport(&mut command)?;

    let child_stdin = child.stdin.take().context("serve helper stdin")?;
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

    // First frame on stdin: the serve config (TLS material + initial size).
    let mut helper_stdin = FramedWrite::new(child_stdin, helper_codec());
    let config = ServeConfig {
        cert_pem,
        key_pem,
        width: DEFAULT_WIDTH,
        height: DEFAULT_HEIGHT,
    };
    let mut config_buf = Vec::new();
    warpgate_rdp_ipc::encode_json_into(&config, &mut config_buf);
    helper_stdin
        .send(bytes::Bytes::copy_from_slice(&config_buf))
        .await?;

    // All subsequent helper stdin writes are funnelled through one task.
    let (helper_in_tx, helper_in_rx) = unbounded_channel::<ServerHelperInput>();
    let stdin_task = tokio::spawn(helper_stdin_writer(helper_stdin, helper_in_rx));

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
    let mut frames = FramedRead::new(stdout, helper_codec());
    let mut backend: Option<BackendBridge> = None;

    while let Some(frame) = frames.next().await {
        let frame = frame.context("reading serve helper output")?;
        let Some(event) = ServerHelperEvent::decode(&frame) else {
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
                match authenticate::<RdpProto>(
                    &services,
                    &server_handle,
                    &username,
                    password,
                    remote_address,
                )
                .await
                {
                    Ok(DesktopAuthOutcome::Authorized {
                        user_info,
                        target,
                        options,
                    }) => {
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
                    Ok(DesktopAuthOutcome::NeedsInteractive(interactive)) => {
                        // Accept the NLA so the RDP session starts, then collect the second
                        // factor (TOTP / web approval) on a Warpgate-rendered holding screen
                        // before connecting to the target.
                        if helper_in_tx
                            .send(ServerHelperInput::AuthResponse { accept: true })
                            .is_err()
                        {
                            break;
                        }
                        match run_hold_screen(&services, &interactive, &mut frames, &helper_in_tx)
                            .await
                        {
                            Ok(Some(user_info)) => {
                                match finalize_user_auth::<RdpProto>(
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
                    Ok(DesktopAuthOutcome::Failed) => {
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

/// RDP's binding to the shared desktop-auth flow.
struct RdpProto;

impl DesktopProtocol for RdpProto {
    type Options = TargetRdpOptions;
    const NAME: &'static str = PROTOCOL_NAME;
    const LABEL: &'static str = "rdp";

    fn options(target: &Target) -> Option<TargetRdpOptions> {
        match &target.options {
            TargetOptions::Rdp(options) => Some(options.clone()),
            _ => None,
        }
    }
}
