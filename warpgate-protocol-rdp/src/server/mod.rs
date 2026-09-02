//! Native RDP server endpoint.
//!
//! Warpgate accepts a raw TCP connection from a standard RDP client (mstsc/FreeRDP) and
//! brokers between two halves:
//!
//! * the viewer-facing [`rdp`] server runs the RDP server state machine and terminates
//!   TLS, and
//! * the target-facing [`crate::client`] (via [`crate::connect`]) drives the RDP client
//!   toward the configured target.
//!
//! Warpgate keeps ownership of the listener, the session/audit lifecycle, and
//! authentication. Credentials the viewer submits arrive as [`ServerEvent::AuthRequest`];
//! Warpgate authenticates them with the same [`AuthSelector`] flow used by the native VNC
//! server, connects to the resolved target, and bridges target framebuffer events back to
//! the viewer while recording them — so native RDP records exactly like the in-browser
//! path.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use futures::FutureExt;
use futures::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncWrite, copy_bidirectional};
use tokio::sync::mpsc::{Sender, UnboundedReceiver, UnboundedSender, channel, unbounded_channel};
use tokio::time::{Instant, timeout_at};
use tracing::{Instrument, debug, error, info, info_span, warn};
use warpgate_common::helpers::net::accept_loop;
use warpgate_common::{ListenEndpoint, TargetRdpOptions};
use warpgate_core::recordings::DesktopRecorder;
use warpgate_core::{
    DesktopInput, Services, State, TargetAuthorization, UserSessionStateInit, WarpgateServerHandle,
};
use warpgate_db_entities::Parameters;
use warpgate_desktop_ui::{DEFAULT_SCREEN_H, DEFAULT_SCREEN_W};

use crate::PROTOCOL_NAME;
use crate::session_handle::RdpSessionHandle;

mod bridge;
mod clipboard;
mod hold_screen;
mod protocol;
mod rdp;

use bridge::connect_backend;
use hold_screen::{run_banner_screen, run_hold_screen};
use protocol::{AuthVerdict, Event as ServerEvent, Input as ServerInput};
use warpgate_desktop_auth::{DesktopAuthOutcome, authenticate, finalize_user_auth};

/// Depth of the feed into the viewer-facing RDP server. Bounded so a slow viewer
/// backpressures `frame_bridge` (and through it the target) rather than letting delta
/// frames queue without limit; kept small so the target paces close to the live edge.
const SERVER_INPUT_CAPACITY: usize = 16;

/// Size of each direction of the in-memory duplex carrying raw RDP bytes between the
/// viewer socket and the RDP server.
const RELAY_BUFFER_BYTES: usize = 64 * 1024;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(120);

/// Handles to the connected target-side RDP client, kept once authentication succeeds.
struct BackendBridge {
    input_tx: Sender<DesktopInput>,
    abort_tx: UnboundedSender<()>,
    frame_bridge: tokio::task::JoinHandle<()>,
    /// Shared with `frame_bridge`; used to record viewer input alongside the
    /// framebuffer. `None` when recording is disabled.
    recorder: Option<Arc<DesktopRecorder>>,
    /// The size the target was dialed at, until the viewer's own negotiated size has been
    /// reconciled against it; `None` once that has happened. A viewer whose buffered input
    /// dials the target before the capability exchange reports its resolution is dialed at
    /// the advertised default, and this is what lets the resolution that follows still reach
    /// the target. Only the viewer's *first* size is its own — every later one echoes a
    /// resize the target itself drove, and re-sending that would fight the target.
    dialed_at: Option<warpgate_desktop_ui::Screen>,
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
    cert_pem: String,
    key_pem: String,
) -> Result<BoxFuture<'static, Result<()>>> {
    let listener = address.tcp_accept_stream().await?;

    Ok(async move {
        accept_loop(
            "RDP connection",
            listener,
            proxy_protocol,
            move |stream, remote_address| {
                let services = services.clone();
                let cert_pem = cert_pem.clone();
                let key_pem = key_pem.clone();
                async move {
                    let (session_handle, mut abort_rx) = RdpSessionHandle::new();

                    let (server_handle, viewer_stream) = State::register_user_session_with_stream(
                        &services.state,
                        PROTOCOL_NAME,
                        UserSessionStateInit {
                            remote_address: Some(remote_address),
                            handle: Box::new(session_handle),
                        },
                        stream,
                    )
                    .await
                    .context("registering session")?;

                    let span =
                        info_span!("RDP", session=%server_handle.lock().await.user_session_id());

                    // The outcome logs run in the span too: anything logged outside it is
                    // not attributed to the session. They are synchronous, so they enter the
                    // span directly rather than nesting another future in this one.
                    tokio::select! {
                        result = handle_connection(
                            services,
                            server_handle.clone(),
                            viewer_stream,
                            remote_address,
                            cert_pem,
                            key_pem,
                        ).instrument(span.clone()) => span.in_scope(|| match result {
                            Ok(()) => info!("Session ended"),
                            Err(error) => error!(%error, "Session failed"),
                        }),
                        _ = abort_rx.recv() => span.in_scope(|| {
                            warn!("Session aborted by admin");
                        }),
                    }
                    Ok(())
                }
            },
        )
        .await;

        Ok(())
    }
    .boxed())
}

async fn handle_connection(
    services: Services,
    server_handle: Arc<tokio::sync::Mutex<WarpgateServerHandle>>,
    mut viewer: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    remote_address: SocketAddr,
    cert_pem: String,
    key_pem: String,
) -> Result<()> {
    // Warpgate owns the viewer socket and the session; `rdp` runs the RDP server state
    // machine over it and terminates TLS toward the viewer.
    let (server_out_tx, server_out_rx) = unbounded_channel::<ServerEvent>();
    // Bounded so a slow viewer backpressures the target losslessly; `frame_bridge` frames
    // and control_loop's occasional auth verdicts share this one ordered feed.
    let (server_in_tx, server_in_rx) = channel::<ServerInput>(SERVER_INPUT_CAPACITY);

    // `ironrdp-server` requires a `Sync` transport, which the session-wrapped viewer
    // stream is not, so the server runs against an in-memory duplex and we relay the raw
    // (TLS) RDP bytes across.
    let (server_side, mut relay_side) = tokio::io::duplex(RELAY_BUFFER_BYTES);
    let mut rdp_done = rdp::run_on_thread(
        server_side,
        cert_pem,
        key_pem,
        (DEFAULT_SCREEN_W, DEFAULT_SCREEN_H),
        server_out_tx,
        server_in_rx,
    );

    // Run the RDP server and the control loop concurrently; whichever ends first tears
    // the session down.
    tokio::select! {
        result = control_loop(services, server_handle, remote_address, server_out_rx, server_in_tx) => {
            result?;
        }
        result = &mut rdp_done => {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => warn!(%error, "RDP server failed"),
                Err(_) => debug!("RDP server ended"),
            }
        }
        result = copy_bidirectional(&mut viewer, &mut relay_side) => {
            if let Err(error) = result {
                debug!(%error, "RDP byte relay error");
            }
        }
    }

    Ok(())
}

/// Read the RDP server's event stream: authenticate the viewer, connect to the target on
/// success, and forward viewer input to the target client.
async fn control_loop(
    services: Services,
    server_handle: Arc<tokio::sync::Mutex<WarpgateServerHandle>>,
    remote_address: SocketAddr,
    mut events: UnboundedReceiver<ServerEvent>,
    server_in_tx: Sender<ServerInput>,
) -> Result<()> {
    let mut backend: Option<BackendBridge> = None;
    // Authorized target awaiting the first `Size` event before we dial it. The RDP
    // sequence delivers the viewer's credentials (CredSSP) *before* its desktop size
    // (capability exchange), so we hold the authorized target here and dial once the
    // negotiated resolution arrives — otherwise the target would be dialed at the
    // pre-negotiation default and the whole session would run at that size.
    let mut pending_dial: Option<PendingDial> = None;
    // What the RDP server settled on with the viewer, which is what we ask the target for.
    // Seeded with the size we advertised, used only if the viewer never negotiates one.
    let mut screen = warpgate_desktop_ui::Screen {
        width: DEFAULT_SCREEN_W,
        height: DEFAULT_SCREEN_H,
    };

    let handshake_deadline = Instant::now() + HANDSHAKE_TIMEOUT;

    loop {
        // Bound the wait only until the target is dialed; once `backend` is set the
        // established proxy session runs without a time limit.
        let event = if backend.is_some() {
            events.recv().await
        } else {
            timeout_at(handshake_deadline, events.recv())
                .await
                .map_err(|_| anyhow!("RDP pre-authorization handshake timed out"))?
        };
        let Some(event) = event else {
            break;
        };
        let input = match event {
            ServerEvent::AuthRequest {
                username,
                password,
                reply,
            } => {
                if backend.is_some() || pending_dial.is_some() {
                    // Already authenticated (dialed, or awaiting the size to dial); reject a
                    // duplicate request by dropping its reply rather than answering twice.
                    continue;
                }
                match authenticate::<TargetRdpOptions>(
                    &services,
                    &server_handle,
                    &username,
                    password,
                    remote_address,
                )
                .await
                {
                    Ok(DesktopAuthOutcome::Authorized { authorization }) => {
                        // Accept the NLA so the capability exchange proceeds and reports
                        // the viewer's desktop size; defer the target dial to that `Size`.
                        if reply.send(AuthVerdict::StartSession).is_err() {
                            break;
                        }
                        pending_dial = Some(authorization);
                        // The banner screen consumes the viewer's `Size` event while it waits,
                        // so dial here once it's dismissed rather than waiting for a `Size`
                        // that has already been delivered.
                        match acknowledge_banner(&services, &mut events, &server_in_tx, &mut screen)
                            .await?
                        {
                            BannerOutcome::NotShown => (),
                            BannerOutcome::Acknowledged => {
                                dial_if_pending(
                                    &mut backend,
                                    &mut pending_dial,
                                    &services,
                                    &server_handle,
                                    &server_in_tx,
                                    screen,
                                )
                                .await?;
                            }
                            BannerOutcome::Disconnected => break,
                        }
                    }
                    Ok(DesktopAuthOutcome::NeedsInteractive(interactive)) => {
                        // Accept the NLA so the RDP session starts, then collect the second
                        // factor (TOTP / web approval) on a Warpgate-rendered holding screen
                        // before connecting to the target.
                        if reply.send(AuthVerdict::StartSession).is_err() {
                            break;
                        }
                        match run_hold_screen(
                            &services,
                            &interactive,
                            &mut events,
                            &server_in_tx,
                            &mut screen,
                        )
                        .await
                        {
                            Ok(Some(identity)) => {
                                match finalize_user_auth::<TargetRdpOptions>(
                                    &services,
                                    &identity,
                                    &interactive.target_name,
                                )
                                .await
                                {
                                    Ok(authorization) => {
                                        // `screen` was updated by `run_hold_screen` as the
                                        // viewer negotiated its size during the 2FA prompt.
                                        pending_dial = Some(authorization);
                                        if matches!(
                                            acknowledge_banner(
                                                &services,
                                                &mut events,
                                                &server_in_tx,
                                                &mut screen,
                                            )
                                            .await?,
                                            BannerOutcome::Disconnected
                                        ) {
                                            break;
                                        }
                                        dial_if_pending(
                                            &mut backend,
                                            &mut pending_dial,
                                            &services,
                                            &server_handle,
                                            &server_in_tx,
                                            screen,
                                        )
                                        .await?;
                                    }
                                    Err(error) => {
                                        warn!(%error, "Authorization failed after second factor");
                                        let _ = server_in_tx.send(ServerInput::Shutdown).await;
                                        break;
                                    }
                                }
                            }
                            Ok(None) => {
                                warn!("Interactive authentication failed");
                                let _ = server_in_tx.send(ServerInput::Shutdown).await;
                                break;
                            }
                            Err(error) => {
                                warn!(%error, "Holding-screen error");
                                let _ = server_in_tx.send(ServerInput::Shutdown).await;
                                break;
                            }
                        }
                    }
                    Ok(DesktopAuthOutcome::Failed) => {
                        warn!("Authentication failed");
                        let _ = reply.send(AuthVerdict::Deny);
                    }
                    Err(error) => {
                        warn!(%error, "Authentication error");
                        let _ = reply.send(AuthVerdict::Deny);
                    }
                }
                continue;
            }
            ServerEvent::Size { width, height } => {
                screen = warpgate_desktop_ui::Screen { width, height };
                dial_if_pending(
                    &mut backend,
                    &mut pending_dial,
                    &services,
                    &server_handle,
                    &server_in_tx,
                    screen,
                )
                .await?;
                // A target dialed before this arrived is running at the advertised default,
                // so bring it to the resolution the viewer actually negotiated. `take` spends
                // the reconciliation whether or not it resizes anything, so the `Size` a
                // target-driven resize echoes back here is never bounced at the target.
                if let Some(backend) = &mut backend
                    && let Some(dialed_at) = backend.dialed_at.take()
                    && dialed_at != screen
                    && backend
                        .input_tx
                        .send(DesktopInput::Resize { width, height })
                        .await
                        .is_err()
                {
                    break;
                }
                continue;
            }
            ServerEvent::ResizeRequest { width, height } => {
                if let Some(backend) = &mut backend {
                    // The viewer is driving the size itself now; reconciling the dial size
                    // afterwards could only replay a stale one.
                    backend.dialed_at = None;
                    if backend
                        .input_tx
                        .send(DesktopInput::Resize { width, height })
                        .await
                        .is_err()
                    {
                        break;
                    }
                } else if server_in_tx
                    .send(ServerInput::Resize { width, height })
                    .await
                    .is_err()
                {
                    break;
                }
                continue;
            }
            // Viewer input: record it for audit (like native VNC) then forward to the
            // target. `break` once the target client is gone (send fails).
            ServerEvent::Input(input) => input,
        };

        // A viewer that never negotiates a size won't emit `Size`; dial the pending target on
        // its first input so the session still connects (at the advertised default). Input the
        // viewer sent during the handshake is delivered ahead of the negotiated size, so this
        // also fires for viewers that do negotiate one — the `Size` arm resizes the target once
        // that size arrives.
        dial_if_pending(
            &mut backend,
            &mut pending_dial,
            &services,
            &server_handle,
            &server_in_tx,
            screen,
        )
        .await?;

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

/// An authorized target held until the viewer's negotiated size is known.
type PendingDial = TargetAuthorization<TargetRdpOptions>;

enum BannerOutcome {
    /// No banner is configured, so nothing was rendered and no events were consumed.
    NotShown,
    /// The viewer acknowledged the banner; its negotiated size is now in `screen`.
    Acknowledged,
    Disconnected,
}

/// Show the login banner, if one is configured, and wait for the viewer to acknowledge it.
async fn acknowledge_banner(
    services: &Services,
    events: &mut UnboundedReceiver<ServerEvent>,
    server_in_tx: &Sender<ServerInput>,
    screen: &mut warpgate_desktop_ui::Screen,
) -> Result<BannerOutcome> {
    let Some(banner) = Parameters::Entity::get(&services.db)
        .await?
        .banner_text()
        .map(str::to_owned)
    else {
        return Ok(BannerOutcome::NotShown);
    };
    Ok(
        if run_banner_screen(&banner, events, server_in_tx, screen).await? {
            BannerOutcome::Acknowledged
        } else {
            BannerOutcome::Disconnected
        },
    )
}

/// Dial the pending target, if there is one and it hasn't been dialed yet, at `screen`.
async fn dial_if_pending(
    backend: &mut Option<BackendBridge>,
    pending: &mut Option<PendingDial>,
    services: &Services,
    server_handle: &Arc<tokio::sync::Mutex<WarpgateServerHandle>>,
    server_in_tx: &Sender<ServerInput>,
    screen: warpgate_desktop_ui::Screen,
) -> Result<()> {
    if backend.is_none()
        && let Some(authorization) = pending.take()
    {
        *backend = Some(
            connect_backend(services, server_handle, server_in_tx, authorization, screen).await?,
        );
    }
    Ok(())
}
