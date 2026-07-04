mod protocol;
mod rfb;
mod session_handle;

use std::collections::{HashSet, VecDeque};
use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures::FutureExt;
use futures::future::BoxFuture;
use rustls::ServerConfig;
use rustls::server::NoClientAuth;
use tokio::io::{AsyncRead, AsyncWrite, copy_bidirectional};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, sleep, timeout_at};
use tokio_rustls::TlsAcceptor;
use tokio_stream::StreamExt;
use tracing::{Instrument, debug, error, info, info_span, warn};
use uuid::Uuid;
use warpgate_common::auth::{
    AuthCredential, AuthResult, AuthSelector, AuthState, AuthStateUserInfo, CredentialKind,
};
use warpgate_common::helpers::net::detect_port_knock;
use warpgate_common::helpers::otp::OTP_DIGITS;
use warpgate_common::{
    ListenEndpoint, Secret, Target, TargetOptions, TargetVncOptions, VncTargetAuth,
};
use warpgate_common_http::ext::construct_external_url;
use warpgate_core::auth::validate_and_add_credential;
use warpgate_core::login_protection::FailedAttemptInfo;
use warpgate_core::recordings::{DesktopRecorder, DesktopRecordingMetadata};
use warpgate_core::{
    ConfigProvider, DesktopEvent, DesktopInput, DesktopState, Services, SessionStateInit, State,
    WarpgateServerHandle, authorize_ticket, consume_ticket,
};
use warpgate_protocol_vnc_ui as ui;
use warpgate_tls::{ResolveServerCert, TlsCertificateAndPrivateKey};

use self::protocol::{
    ClientEvent, DEFAULT_PIXEL_FORMAT, PixelFormat, forward_format_setup, pack_bgra, pack_rgb,
    parse_server_init_size, read_client_messages, write_desktop_size,
    write_framebuffer_update_request, write_raw_rect, write_server_cut_text, write_server_init,
};
use self::rfb::{
    SecurityType, backend_handshake, server_apple_dh_auth, server_negotiate_security,
    server_read_client_init, server_read_plain_credentials, server_vencrypt_sub_negotiate,
    server_write_security_result,
};
use self::session_handle::VncSessionHandle;
use crate::PROTOCOL_NAME;

pub async fn bind_server(
    services: Services,
    address: ListenEndpoint,
    certificate_and_key: TlsCertificateAndPrivateKey,
) -> Result<BoxFuture<'static, Result<()>>> {
    let tls_config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_client_cert_verifier(Arc::new(NoClientAuth))
    .with_cert_resolver(Arc::new(ResolveServerCert(Arc::new(
        certificate_and_key.into(),
    ))));
    let tls_config = Arc::new(tls_config);

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

            let tls_config = tls_config.clone();
            let services = services.clone();
            tokio::spawn(async move {
                let (session_handle, mut abort_rx) = VncSessionHandle::new();

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

                let span = info_span!("VNC", session=%server_handle.lock().await.id());

                tokio::select! {
                    result = handle_connection(
                        services,
                        server_handle.clone(),
                        stream,
                        tls_config,
                        remote_address,
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

/// A timeout for the case where the client stalls after
/// we announce security types (e.g. macOS Screen Sharing)
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(120);

/// Sanity bound
const MAX_STRING_LEN: usize = 4096;

// Boxed to erase types
trait ViewerStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ViewerStream for T {}

async fn handle_connection(
    services: Services,
    server_handle: Arc<tokio::sync::Mutex<WarpgateServerHandle>>,
    stream: TcpStream,
    tls_config: Arc<ServerConfig>,
    remote_address: SocketAddr,
) -> Result<()> {
    let stream = {
        let guard = server_handle.lock().await;
        guard.wrap_stream(stream).await?
    };

    // Bound the whole handshake + auth phase with a single timeout, so a viewer that
    // can't speak our auth (or stalls) is dropped with an error instead of hanging.
    // The relay afterwards is intentionally untimed.
    let Some(session) = timeout_at(
        Instant::now() + HANDSHAKE_TIMEOUT,
        negotiate_and_authorize(
            stream,
            &services,
            &server_handle,
            tls_config,
            remote_address,
        ),
    )
    .await
    .map_err(|_| {
        anyhow!("VNC handshake timed out; the viewer may not support our authentication")
    })??
    else {
        // `None` = authentication was rejected (failure result already sent), quit
        return Ok(());
    };

    // The relay/recording loop afterwards is intentionally untimed.
    match session {
        AuthorizedSession::Relay {
            mut viewer,
            mut backend,
        } => {
            debug!("starting bidirectional relay");
            copy_bidirectional(&mut viewer, &mut backend)
                .await
                .context("relaying VNC session")?;
        }
        AuthorizedSession::Record(session) => {
            debug!("starting recording session");
            run_recording_session(*session).await?;
        }
    }

    Ok(())
}

/// Negotiate security, authenticate the viewer, and connect + handshake the backend
async fn negotiate_and_authorize(
    mut stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    services: &Services,
    server_handle: &Arc<tokio::sync::Mutex<WarpgateServerHandle>>,
    tls_config: Arc<ServerConfig>,
    remote_address: SocketAddr,
) -> Result<Option<AuthorizedSession>> {
    // ProtocolVersion + security-type negotiation, then branch per chosen type to get
    // the (possibly TLS-upgraded) viewer stream and the credentials it carries.
    let (mut viewer, username, password): (Box<dyn ViewerStream>, _, _) =
        match server_negotiate_security(&mut stream).await? {
            SecurityType::VeNCrypt => {
                server_vencrypt_sub_negotiate(&mut stream).await?;
                let mut tls = TlsAcceptor::from(tls_config)
                    .accept(stream)
                    .await
                    .context("TLS handshake")?;
                let (username, password) = server_read_plain_credentials(&mut tls).await?;
                (Box::new(tls), username, password)
            }
            SecurityType::AppleDh => {
                let (username, password) = server_apple_dh_auth(&mut stream).await?;
                (Box::new(stream), username, password)
            }
            SecurityType::None | SecurityType::VncAuth => {
                bail!("unexpected non-viewer security type negotiated")
            }
        };

    let authenticated =
        match authenticate(services, server_handle, &username, password, remote_address).await {
            Ok(Some(a)) => a,
            Ok(None) => {
                warn!("Authentication failed");
                server_write_security_result(&mut viewer, false, "Authentication failed")
                    .await
                    .ok();
                return Ok(None);
            }
            Err(error) => {
                warn!(%error, "Authentication error");
                server_write_security_result(&mut viewer, false, "Authentication failed")
                    .await
                    .ok();
                return Ok(None);
            }
        };

    server_write_security_result(&mut viewer, true, "").await?;
    let shared_flag = server_read_client_init(&mut viewer).await?;

    // We render our own framebuffer, so send our own ServerInit
    write_server_init(
        &mut viewer,
        ui::SCREEN_W,
        ui::SCREEN_H,
        &DEFAULT_PIXEL_FORMAT,
        "Warpgate",
    )
    .await?;

    let (viewer_rd, mut viewer_wr) = tokio::io::split(viewer);
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let (stop_tx, stop_rx) = oneshot::channel();
    let reader = tokio::spawn(read_client_messages(viewer_rd, events_tx, stop_rx));

    let mut render = RenderState::new();

    let (user_info, target, vnc_options) = match authenticated {
        VncAuthState::Ready {
            user_info,
            target,
            options,
        } => (user_info, target, options),
        VncAuthState::NeedsInteractive {
            state_id,
            username,
            target_name,
        } => {
            collect_additional_credentials(
                &mut viewer_wr,
                &mut events_rx,
                &mut render,
                services,
                state_id,
                &username,
                remote_address.ip(),
            )
            .await?;

            let user_info = services
                .auth_state_store
                .lock()
                .await
                .get(&state_id)
                .context("auth state expired during approval")?
                .lock()
                .await
                .user_info()
                .clone();
            let (target, options) = finalize_user_auth(services, &username, &target_name).await?;
            // Interactive (TOTP / web-approval) auth fully succeeded: clear any failed
            // attempts, mirroring the password-only `Accepted` path in `authenticate` and
            // the SSH baseline, which clears counters once 2FA completes. Fail open.
            let _ = services
                .login_protection
                .clear_failed_attempts(&remote_address.ip(), &user_info.username)
                .await;
            (user_info, target, options)
        }
    };

    {
        let handle = server_handle.lock().await;
        handle.set_user_info(user_info).await?;
        handle.set_target(&target).await?;
    }

    info!(target=%target.name, "Authorized");

    // Decide whether to record. With recording disabled we keep the original, fully
    // transparent RFB relay (byte-for-byte unchanged, no re-encoding). With a recording
    // active we instead decode the backend and re-encode toward the viewer so the
    // framebuffer can be captured and viewer input forwarded.
    let session_id = server_handle.lock().await.id();
    let recorder = match services
        .recordings
        .lock()
        .await
        .start::<DesktopRecorder, _>(&session_id, None, DesktopRecordingMetadata)
        .await
    {
        Ok(recorder) => Some(recorder),
        Err(warpgate_core::recordings::Error::Disabled) => None,
        Err(error) => {
            warn!(%error, "Failed to start VNC session recording");
            None
        }
    };

    let Some(recorder) = recorder else {
        // === Transparent relay (recording disabled) — unchanged behaviour ===
        let target_password = match &vnc_options.auth {
            VncTargetAuth::Password(auth) => auth.password.expose_secret().clone(),
            VncTargetAuth::None(_) => String::new(),
        };

        // Render hold screen while connecting
        debug!(host = %vnc_options.host, port = vnc_options.port, "connecting to backend");
        let (mut backend, backend_init) =
            render_while(&mut viewer_wr, &mut events_rx, &mut render, async {
                let mut backend = TcpStream::connect((vnc_options.host.as_str(), vnc_options.port))
                    .await
                    .context("connecting to VNC target")?;
                backend.set_nodelay(true).ok();
                let server_init =
                    backend_handshake(&mut backend, &target_password, shared_flag).await?;
                Ok::<_, anyhow::Error>((backend, server_init))
            })
            .await??;

        // Stop the reader and retrieve the stream
        let _ = stop_tx.send(());
        let viewer_rd = reader.await.context("joining viewer reader")??;

        // Apply any events the reader emitted just before stopping (final pixel format/encodings)
        while let Ok(event) = events_rx.try_recv() {
            render.note_event(Some(event));
        }

        let mut viewer = viewer_rd.unsplit(viewer_wr);

        let (backend_w, backend_h) = parse_server_init_size(&backend_init)?;

        // Tell backend the viewer's pixel format / encodings and request a frame
        forward_format_setup(
            &mut backend,
            &render.pixel_format,
            render.encodings.as_deref(),
        )
        .await?;
        write_framebuffer_update_request(&mut backend, false, 0, 0, backend_w, backend_h).await?;

        // Resize the viewer to match backend geometry (only if it advertised DesktopSize)
        if render.supports_desktop_size {
            write_desktop_size(&mut viewer, backend_w, backend_h).await?;
        } else {
            warn!(
                backend_w,
                backend_h, "viewer did not advertise DesktopSize - skipping resize"
            );
        }

        return Ok(Some(AuthorizedSession::Relay { viewer, backend }));
    };

    // === Recording session (recording active) — decode & re-encode ===
    // A single backend client connection (shared-mode is irrelevant — we never open a
    // second one). Tight/CopyRect/cursor are dropped (see RECORDING_ENCODINGS) so every
    // update arrives as plain BGRA we can both record and re-encode as an RFB Raw rect.
    debug!(host = %vnc_options.host, port = vnc_options.port, "connecting to backend for recording");
    let mut backend = crate::client::connect_for_recording(vnc_options.clone());

    // Wait under the hold screen for the backend's initial geometry, recording every
    // event consumed so nothing is dropped from the recording.
    let (backend_w, backend_h) = render_while(
        &mut viewer_wr,
        &mut events_rx,
        &mut render,
        wait_for_backend_size(&mut backend.event_rx, &recorder),
    )
    .await??;

    // Resize the viewer to match backend geometry (parity with the transparent path).
    if render.supports_desktop_size {
        write_desktop_size(&mut viewer_wr, backend_w, backend_h).await?;
    } else {
        warn!(
            backend_w,
            backend_h, "viewer did not advertise DesktopSize - skipping resize"
        );
    }

    Ok(Some(AuthorizedSession::Record(Box::new(
        RecordingSession {
            viewer_wr,
            viewer_events: events_rx,
            reader,
            stop_tx,
            render,
            backend,
            recorder,
        },
    ))))
}

/// A negotiated, authorized session ready to run. Either a fully transparent byte
/// relay (recording disabled) or a decode-and-re-encode recording session.
#[allow(clippy::large_enum_variant)]
enum AuthorizedSession {
    Relay {
        viewer: Box<dyn ViewerStream>,
        backend: TcpStream,
    },
    Record(Box<RecordingSession>),
}

/// State handed off to [`run_recording_session`] after the handshake completes.
struct RecordingSession {
    viewer_wr: tokio::io::WriteHalf<Box<dyn ViewerStream>>,
    viewer_events: mpsc::UnboundedReceiver<ClientEvent>,
    reader: tokio::task::JoinHandle<Result<tokio::io::ReadHalf<Box<dyn ViewerStream>>>>,
    stop_tx: oneshot::Sender<()>,
    render: RenderState,
    backend: crate::client::VncClientHandles,
    recorder: DesktopRecorder,
}

/// Record an event, logging (but not failing on) recorder write errors.
async fn record_event(recorder: &DesktopRecorder, event: &DesktopEvent) {
    if let Err(error) = recorder.write_event(event).await {
        warn!(%error, "Failed to record VNC desktop event");
    }
}

/// Record a viewer input, logging (but not failing on) recorder write errors.
async fn record_input(recorder: &DesktopRecorder, input: &DesktopInput) {
    if let Err(error) = recorder.write_input(input).await {
        warn!(%error, "Failed to record VNC viewer input");
    }
}

/// Drain backend events until the first [`DesktopEvent::Resize`] reveals the framebuffer
/// geometry, recording each consumed event. The backend client always emits `Resize`
/// before any `RawImage`, so nothing visible is consumed here.
async fn wait_for_backend_size(
    event_rx: &mut mpsc::Receiver<DesktopEvent>,
    recorder: &DesktopRecorder,
) -> Result<(u16, u16)> {
    while let Some(event) = event_rx.recv().await {
        record_event(recorder, &event).await;
        match event {
            DesktopEvent::Resize { width, height } => return Ok((width, height)),
            DesktopEvent::Error(message) => bail!("backend error before first frame: {message}"),
            DesktopEvent::State(DesktopState::Disconnected) => {
                bail!("backend disconnected before first frame")
            }
            _ => {}
        }
    }
    bail!("backend channel closed before first frame")
}

/// Re-encode one queued backend frame toward the viewer in response to an outstanding
/// `FramebufferUpdateRequest`. Clears `pending_request` once a frame is actually sent.
async fn flush_frame<W>(
    viewer_wr: &mut W,
    render: &mut RenderState,
    event: DesktopEvent,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    match event {
        DesktopEvent::RawImage { rect, data } => {
            let pixels = pack_bgra(&render.pixel_format, &data);
            write_raw_rect(viewer_wr, rect.x, rect.y, rect.width, rect.height, &pixels).await?;
            render.pending_request = false;
        }
        DesktopEvent::Resize { width, height } if render.supports_desktop_size => {
            write_desktop_size(viewer_wr, width, height).await?;
            render.pending_request = false;
        }
        // A resize the viewer can't be told about: drop it but keep the request pending
        // so the next real frame still satisfies it. Other variants never reach the queue.
        _ => {}
    }
    Ok(())
}

/// The decode-and-re-encode loop: pump backend `DesktopEvent`s to the viewer as RFB
/// (recording each), and forward viewer input back to the backend. Lockstep — at most
/// one rect per `FramebufferUpdateRequest` — with a bounded queue providing end-to-end
/// backpressure when the viewer is slow. Dropping the recorder finalises the recording.
async fn run_recording_session(session: RecordingSession) -> Result<()> {
    /// Bound on queued-but-unflushed backend frames before we stop draining the backend.
    const QUEUE_CAP: usize = 256;

    let RecordingSession {
        mut viewer_wr,
        mut viewer_events,
        reader,
        stop_tx,
        mut render,
        backend,
        recorder,
    } = session;
    let crate::client::VncClientHandles {
        mut event_rx,
        input_tx,
        abort_tx,
    } = backend;

    let mut queue: VecDeque<DesktopEvent> = VecDeque::new();

    let result = loop {
        // Satisfy an outstanding request with one queued frame before blocking again.
        if render.pending_request
            && let Some(event) = queue.pop_front()
        {
            if let Err(error) = flush_frame(&mut viewer_wr, &mut render, event).await {
                break Err(error);
            }
            continue;
        }

        tokio::select! {
            biased;

            // Viewer → us: input to forward, plus pixel-format/encoding/refresh updates.
            event = viewer_events.recv() => {
                match event {
                    Some(ClientEvent::WantsFrame) => render.pending_request = true,
                    Some(ClientEvent::PixelFormat(pf)) => render.pixel_format = pf,
                    Some(ClientEvent::Encodings { raw, desktop_size }) => {
                        render.encodings = Some(raw);
                        render.supports_desktop_size = desktop_size;
                    }
                    Some(ClientEvent::Key { down, keysym }) => {
                        let input = DesktopInput::Key { keysym, down };
                        record_input(&recorder, &input).await;
                        if input_tx.send(input).await.is_err() {
                            break Ok(());
                        }
                    }
                    Some(ClientEvent::Pointer { x, y, buttons }) => {
                        let input = DesktopInput::Pointer { x, y, buttons };
                        record_input(&recorder, &input).await;
                        if input_tx.send(input).await.is_err() {
                            break Ok(());
                        }
                    }
                    Some(ClientEvent::Clipboard(text)) => {
                        let input = DesktopInput::Clipboard(text);
                        record_input(&recorder, &input).await;
                        let _ = input_tx.send(input).await;
                    }
                    None => break Ok(()), // viewer disconnected
                }
            }

            // Backend → us: record every event, queue frames, mirror clipboard. Gated so
            // a slow viewer back-pressures the backend instead of growing the queue.
            event = event_rx.recv(), if queue.len() < QUEUE_CAP => {
                match event {
                    Some(event) => {
                        record_event(&recorder, &event).await;
                        match event {
                            DesktopEvent::RawImage { .. } | DesktopEvent::Resize { .. } => {
                                queue.push_back(event);
                            }
                            DesktopEvent::Clipboard(text) => {
                                if let Err(error) = write_server_cut_text(&mut viewer_wr, &text).await {
                                    break Err(error);
                                }
                            }
                            DesktopEvent::State(DesktopState::Disconnected) => break Ok(()),
                            DesktopEvent::Error(message) => break Err(anyhow!("backend error: {message}")),
                            // RECORDING_ENCODINGS rules out Jpeg/CopyRect/Cursor; Bell/State ignored.
                            _ => {}
                        }
                    }
                    None => break Ok(()), // backend ended
                }
            }
        }
    };

    // Teardown: stop the viewer reader and the backend client. Dropping `recorder`
    // (held until here) finalises the recording.
    let _ = stop_tx.send(());
    let _ = abort_tx.send(());
    reader.abort();
    drop(recorder);

    result
}

/// Shared state for the hold screen
struct RenderState {
    pixel_format: PixelFormat,
    encodings: Option<Vec<u8>>,
    supports_desktop_size: bool,
    pending_request: bool,
    reader_done: bool,
    tick: u64,
}

impl RenderState {
    const fn new() -> Self {
        Self {
            pixel_format: DEFAULT_PIXEL_FORMAT,
            encodings: None,
            supports_desktop_size: false,
            pending_request: false,
            reader_done: false,
            tick: 0,
        }
    }

    /// Update state from a viewer message
    /// Returns keysym of a keypress (the only interesting action)
    fn note_event(&mut self, event: Option<ClientEvent>) -> Option<u32> {
        match event {
            Some(ClientEvent::PixelFormat(pf)) => self.pixel_format = pf,
            Some(ClientEvent::Encodings { raw, desktop_size }) => {
                self.encodings = Some(raw);
                self.supports_desktop_size = desktop_size;
            }
            Some(ClientEvent::WantsFrame) => self.pending_request = true,
            Some(ClientEvent::Key { down: true, keysym }) => return Some(keysym),
            // A key release, pointer motion or clipboard update is irrelevant to the
            // hold screen; the recording session loop handles input once it takes over.
            Some(
                ClientEvent::Key { .. } | ClientEvent::Pointer { .. } | ClientEvent::Clipboard(_),
            ) => {}
            None => self.reader_done = true,
        }
        None
    }

    async fn paint<W, R>(&mut self, viewer_wr: &mut W, render_frame: R) -> Result<()>
    where
        W: AsyncWrite + Unpin,
        R: FnOnce(u64) -> Result<Vec<u8>, Infallible>,
    {
        let image = render_frame(self.tick)?;
        let pixels = pack_rgb(&self.pixel_format, &image);
        write_raw_rect(viewer_wr, 0, 0, ui::SCREEN_W, ui::SCREEN_H, &pixels).await?;
        self.tick += 1;
        self.pending_request = false;
        Ok(())
    }
}

/// Render the hold screen while awaiting future
async fn render_while<W, F>(
    viewer_wr: &mut W,
    events_rx: &mut mpsc::UnboundedReceiver<ClientEvent>,
    state: &mut RenderState,
    wait: F,
) -> Result<F::Output>
where
    W: AsyncWrite + Unpin,
    F: Future,
{
    tokio::pin!(wait);
    loop {
        tokio::select! {
            out = &mut wait => return Ok(out),
            event = events_rx.recv(), if !state.reader_done => {
                state.note_event(event);
            }
            // Only render when asked to
            () = sleep(SPINNER_INTERVAL), if state.pending_request => {
                state.paint(viewer_wr, ui::render_connecting).await?;
            }
        }
    }
}

/// ui animation frame interval while connecting to the backend
const SPINNER_INTERVAL: Duration = Duration::from_millis(30);

/// Render hold screen UI while collecting OTP/waiting for web auth
async fn collect_additional_credentials<W>(
    viewer_wr: &mut W,
    events_rx: &mut mpsc::UnboundedReceiver<ClientEvent>,
    render: &mut RenderState,
    services: &Services,
    state_id: Uuid,
    username: &str,
    remote_ip: IpAddr,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let state = services
        .auth_state_store
        .lock()
        .await
        .get(&state_id)
        .context("auth state expired")?;

    let mut otp = String::new();
    let mut otp_failures = 0usize;
    let mut approval = services.auth_state_store.lock().await.subscribe(state_id);

    async fn next_prompt(
        services: &Services,
        state: &Arc<tokio::sync::Mutex<AuthState>>,
        kinds: HashSet<CredentialKind>,
        otp: &str,
    ) -> Option<ui::AuthPrompt> {
        if kinds.contains(&CredentialKind::Totp) {
            Some(ui::AuthPrompt::Otp {
                entered: otp.to_owned(),
            })
        } else if kinds.contains(&CredentialKind::WebUserApproval) {
            Some(ui::AuthPrompt::WebApproval {
                url: web_approval_url(services, state).await,
                security_key: state.lock().await.identification_string().to_owned(),
            })
        } else {
            None
        }
    }

    'next_prompt: loop {
        let need = match state.lock().await.verify() {
            AuthResult::Accepted { .. } => return Ok(()),
            AuthResult::Rejected => bail!("VNC authentication rejected"),
            AuthResult::Need(need) => need,
        };

        let Some(prompt) = next_prompt(services, &state, need, &otp).await else {
            bail!("authentication policy requires a factor that cannot be collected over VNC");
        };

        if let ui::AuthPrompt::WebApproval { url, .. } = &prompt {
            if let Some(url) = url {
                write_server_cut_text(viewer_wr, &url).await.ok();
            }
        }

        loop {
            tokio::select! {
                // Browser approval landed (or the signal lagged/closed); the loop re-verifies.
                _ = approval.recv(), if matches!(prompt, ui::AuthPrompt::WebApproval { ..}) => {
                    continue 'next_prompt // web approval accepted
                }
                event = events_rx.recv(), if !render.reader_done => {
                    if let Some(keysym) = render.note_event(event)
                        && matches!(prompt, ui::AuthPrompt::Otp { ..})
                    {
                        if handle_otp_keypress(keysym, &mut otp, services, &state, username, remote_ip)
                            .await
                        {
                            otp_failures += 1;
                            if otp_failures >= MAX_OTP_ATTEMPTS {
                                bail!("too many incorrect one-time passwords");
                            }
                        }
                        render.pending_request = true; // reflect the input on the next paint
                        continue 'next_prompt // OTP might have been accepted or rejected
                    }
                }
                () = sleep(SPINNER_INTERVAL), if render.pending_request => {
                    render.paint(viewer_wr, |tick| ui::render_authentication(tick, &prompt)).await?;
                }
            }
        }
    }
}

// X11 keysyms accepted in the OTP field
const KEYSYM_DIGIT_0: u32 = 0x0030;
const KEYSYM_DIGIT_9: u32 = 0x0039;
const KEYSYM_KP_0: u32 = 0xFFB0;
const KEYSYM_KP_9: u32 = 0xFFB9;
const KEYSYM_BACKSPACE: u32 = 0xFF08;
const KEYSYM_RETURN: u32 = 0xFF0D;
const KEYSYM_KP_ENTER: u32 = 0xFF8D;

const MAX_OTP_ATTEMPTS: usize = 3;

async fn handle_otp_keypress(
    keysym: u32,
    otp: &mut String,
    services: &Services,
    state: &Arc<tokio::sync::Mutex<AuthState>>,
    username: &str,
    remote_ip: IpAddr,
) -> bool {
    let mut submit = false;
    match keysym {
        KEYSYM_DIGIT_0..=KEYSYM_DIGIT_9 if otp.len() < OTP_DIGITS => {
            otp.push(char::from(keysym as u8));
            submit = otp.len() == OTP_DIGITS;
        }
        KEYSYM_KP_0..=KEYSYM_KP_9 if otp.len() < OTP_DIGITS => {
            otp.push(char::from(b'0' + (keysym - KEYSYM_KP_0) as u8));
            submit = otp.len() == OTP_DIGITS;
        }
        KEYSYM_BACKSPACE => {
            otp.pop();
        }
        KEYSYM_RETURN | KEYSYM_KP_ENTER => submit = true,
        _ => {}
    }

    if submit {
        let credential = AuthCredential::Otp(Secret::new(std::mem::take(otp)));
        // Route through the shared helper so a bad OTP emits the same
        // UserAuthenticationFailed1 audit event as the other protocols.
        let valid = validate_and_add_credential(
            &mut *state.lock().await,
            &credential,
            &mut *services.config_provider.lock().await,
        )
        .await
        .unwrap_or(false);
        if !valid {
            warn!("Incorrect one-time password");
            let _ = services
                .login_protection
                .record_failed_attempt(FailedAttemptInfo {
                    username: username.to_string(),
                    remote_ip,
                    protocol: "vnc".to_string(),
                    credential_type: "otp".to_string(),
                })
                .await;
            return true;
        }
    }
    false
}

#[allow(clippy::large_enum_variant)]
enum VncAuthState {
    Ready {
        user_info: AuthStateUserInfo,
        target: Target,
        options: TargetVncOptions,
    },
    NeedsInteractive {
        state_id: Uuid,
        username: String,
        target_name: String,
    },
}

/// Validate the initial VNC auth
async fn authenticate(
    services: &Services,
    server_handle: &Arc<tokio::sync::Mutex<WarpgateServerHandle>>,
    selector: &str,
    password: String,
    remote_address: SocketAddr,
) -> Result<Option<VncAuthState>> {
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
                warn!(ip = %remote_ip, "VNC auth attempt from blocked IP");
                return Ok(None);
            }
            if services
                .login_protection
                .check_user_locked(&username)
                .await?
                .is_some()
            {
                warn!(username = %username, "VNC auth attempt for locked user");
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
                    &[
                        CredentialKind::Password,
                        CredentialKind::Totp,
                        CredentialKind::WebUserApproval,
                    ],
                    Some(remote_address.ip()),
                    Some("password"),
                )
                .await?;

            // Password is mandatory, we don't want to serve an anon session
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
                            protocol: "vnc".to_string(),
                            credential_type: "password".to_string(),
                        })
                        .await;
                    return Ok(None);
                }
            }

            let result = state_arc.lock().await.verify();
            match result {
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
                    Ok(Some(VncAuthState::Ready {
                        user_info,
                        target,
                        options,
                    }))
                }

                AuthResult::Need(kinds)
                    if kinds.iter().all(|k| {
                        matches!(k, CredentialKind::Totp | CredentialKind::WebUserApproval)
                    }) =>
                {
                    Ok(Some(VncAuthState::NeedsInteractive {
                        state_id,
                        username,
                        target_name,
                    }))
                }

                // Any other unmet requirement that isn't collectable over VNC
                AuthResult::Need(_) | AuthResult::Rejected => Ok(None),
            }
        }
        AuthSelector::Ticket { secret } => match authorize_ticket(&services.db, &secret).await? {
            Some((ticket, target_model, user_info)) => {
                consume_ticket(&services.db, &ticket.id).await?;
                let (target, options) = find_vnc_target(services, &target_model.name).await?;
                Ok(Some(VncAuthState::Ready {
                    user_info,
                    target,
                    options,
                }))
            }
            None => Ok(None),
        },
    }
}

async fn finalize_user_auth(
    services: &Services,
    username: &str,
    target_name: &str,
) -> Result<(Target, TargetVncOptions)> {
    let authorized = services
        .config_provider
        .lock()
        .await
        .authorize_target(username, target_name)
        .await?;
    if !authorized {
        bail!("Target {target_name} not authorized for {username}");
    }
    find_vnc_target(services, target_name).await
}

async fn web_approval_url(
    services: &Services,
    state: &Arc<tokio::sync::Mutex<AuthState>>,
) -> Option<String> {
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

async fn find_vnc_target(
    services: &Services,
    target_name: &str,
) -> Result<(Target, TargetVncOptions)> {
    let Some(target) = services
        .config_provider
        .lock()
        .await
        .get_target_by_name(target_name)
        .await?
    else {
        bail!("Target {target_name} not found");
    };
    let TargetOptions::Vnc(ref options) = target.options else {
        bail!("Target {target_name} is not a VNC target");
    };
    return Ok((target.clone(), options.clone()));
}
