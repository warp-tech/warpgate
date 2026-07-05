mod bridge;
mod hold_screen;
mod protocol;
mod rfb;
mod session_handle;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures::FutureExt;
use futures::future::BoxFuture;
use rustls::ServerConfig;
use rustls::server::NoClientAuth;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, timeout_at};
use tokio_rustls::TlsAcceptor;
use tokio_stream::StreamExt;
use tracing::{Instrument, debug, error, info, info_span, warn};
use warpgate_common::helpers::net::detect_port_knock;
use warpgate_common::{ListenEndpoint, Target, TargetOptions, TargetVncOptions};
use warpgate_core::recordings::DesktopRecorder;
use warpgate_core::{Services, SessionStateInit, State, WarpgateServerHandle};
use warpgate_desktop_auth::{
    DesktopAuthOutcome, DesktopProtocol, authenticate, finalize_user_auth,
};
use warpgate_desktop_ui as ui;
use warpgate_tls::{ResolveServerCert, TlsCertificateAndPrivateKey};

use self::bridge::{run_proxy_session, wait_for_backend_size};
use self::hold_screen::{collect_additional_credentials, render_while};
use self::protocol::{
    ClientEvent, DEFAULT_PIXEL_FORMAT, PixelFormat, pack_rgb, read_client_messages,
    write_desktop_size, write_raw_rect, write_server_init,
};
use self::rfb::{
    SecurityType, server_apple_dh_auth, server_negotiate_security, server_read_client_init,
    server_read_plain_credentials, server_vencrypt_sub_negotiate, server_write_security_result,
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

    // The proxy loop afterwards is intentionally untimed.
    debug!("starting proxy session");
    run_proxy_session(*session).await?;

    Ok(())
}

/// Negotiate security, authenticate the viewer, and connect + handshake the backend
async fn negotiate_and_authorize(
    mut stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    services: &Services,
    server_handle: &Arc<tokio::sync::Mutex<WarpgateServerHandle>>,
    tls_config: Arc<ServerConfig>,
    remote_address: SocketAddr,
) -> Result<Option<Box<ProxySession>>> {
    let allow_apple_dh = services.config.lock().await.store.vnc.enable_ard_auth;

    // ProtocolVersion + security-type negotiation, then branch per chosen type to get
    // the (possibly TLS-upgraded) viewer stream and the credentials it carries.
    let (mut viewer, username, password): (Box<dyn ViewerStream>, _, _) =
        match server_negotiate_security(&mut stream, allow_apple_dh).await? {
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

    let authenticated = match authenticate::<VncProto>(
        services,
        server_handle,
        &username,
        password,
        remote_address,
    )
    .await
    {
        Ok(DesktopAuthOutcome::Failed) => {
            warn!("Authentication failed");
            server_write_security_result(&mut viewer, false, "Authentication failed")
                .await
                .ok();
            return Ok(None);
        }
        Ok(outcome) => outcome,
        Err(error) => {
            warn!(%error, "Authentication error");
            server_write_security_result(&mut viewer, false, "Authentication failed")
                .await
                .ok();
            return Ok(None);
        }
    };

    server_write_security_result(&mut viewer, true, "").await?;
    // Consume the viewer's ClientInit; its shared-flag is irrelevant because the backend
    // client opens its own connection (always shared) rather than passing this through.
    server_read_client_init(&mut viewer).await?;

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
        DesktopAuthOutcome::Authorized {
            user_info,
            target,
            options,
        } => (user_info, target, options),
        DesktopAuthOutcome::NeedsInteractive(interactive) => {
            collect_additional_credentials(
                &mut viewer_wr,
                &mut events_rx,
                &mut render,
                services,
                interactive.state_id,
                &interactive.username,
                interactive.remote_ip,
            )
            .await?;

            let user_info = services
                .auth_state_store
                .lock()
                .await
                .get(&interactive.state_id)
                .context("auth state expired during approval")?
                .lock()
                .await
                .user_info()
                .clone();
            let (target, options) = finalize_user_auth::<VncProto>(
                services,
                &interactive.username,
                &interactive.target_name,
            )
            .await?;
            // Interactive (TOTP / web-approval) auth fully succeeded: clear any failed
            // attempts, mirroring the password-only `Accepted` path in `authenticate` and
            // the SSH baseline, which clears counters once 2FA completes. Fail open.
            let _ = services
                .login_protection
                .clear_failed_attempts(&interactive.remote_ip, &user_info.username)
                .await;
            (user_info, target, options)
        }
        // Already handled before the security handshake above.
        DesktopAuthOutcome::Failed => return Ok(None),
    };

    {
        let handle = server_handle.lock().await;
        handle.set_user_info(user_info).await?;
        handle.set_target(&target).await?;
    }

    info!(target=%target.name, "Authorized");

    // Start a recording if enabled; `None` just means we don't tap the decoded stream.
    // Either way the session takes the same decode-and-re-encode path below, so the
    // interactive-auth / connecting screens (which render into the viewer framebuffer)
    // keep working and the viewer never needs a JPEG decoder.
    let session_id = server_handle.lock().await.id();
    let recorder = warpgate_desktop_auth::start_recording(services, &session_id, "vnc").await;

    // A single backend client connection decodes every update (Tight/JPEG included, see
    // PROXY_ENCODINGS); we both record it and re-encode it toward the viewer as RFB Raw.
    debug!(host = %vnc_options.host, port = vnc_options.port, "connecting to backend");
    let mut backend = crate::client::connect_for_proxy(vnc_options.clone());

    // Wait under the hold screen for the backend's initial geometry, recording every
    // event consumed so nothing is dropped from the recording.
    let (backend_w, backend_h) = render_while(
        &mut viewer_wr,
        &mut events_rx,
        &mut render,
        wait_for_backend_size(&mut backend.event_rx, &recorder),
    )
    .await??;

    // Resize the viewer to match backend geometry (only if it advertised DesktopSize).
    if render.supports_desktop_size {
        write_desktop_size(&mut viewer_wr, backend_w, backend_h).await?;
    } else {
        warn!(
            backend_w,
            backend_h, "viewer did not advertise DesktopSize - skipping resize"
        );
    }

    Ok(Some(Box::new(ProxySession {
        viewer_wr,
        viewer_events: events_rx,
        reader,
        stop_tx,
        render,
        backend,
        recorder,
    })))
}

/// A negotiated, authorized session ready to run: the single decode-and-re-encode proxy
/// path. `recorder` is `Some` only when session recording is enabled — the byte flow is
/// identical either way, so recorded and unrecorded sessions share one code path.
struct ProxySession {
    viewer_wr: tokio::io::WriteHalf<Box<dyn ViewerStream>>,
    viewer_events: mpsc::UnboundedReceiver<ClientEvent>,
    reader: tokio::task::JoinHandle<Result<tokio::io::ReadHalf<Box<dyn ViewerStream>>>>,
    stop_tx: oneshot::Sender<()>,
    render: RenderState,
    backend: crate::client::VncClientHandles,
    recorder: Option<DesktopRecorder>,
}

/// Shared state for the hold screen
struct RenderState {
    pixel_format: PixelFormat,
    supports_desktop_size: bool,
    /// The viewer negotiated the Tight encoding, so backend JPEG rects can be forwarded
    /// through as Tight/JPEG instead of being decoded and re-encoded as Raw.
    viewer_supports_tight: bool,
    pending_request: bool,
    reader_done: bool,
    tick: u64,
}

impl RenderState {
    const fn new() -> Self {
        Self {
            pixel_format: DEFAULT_PIXEL_FORMAT,
            supports_desktop_size: false,
            viewer_supports_tight: false,
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
            Some(ClientEvent::Encodings {
                desktop_size,
                tight,
            }) => {
                self.supports_desktop_size = desktop_size;
                self.viewer_supports_tight = tight;
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

/// VNC's binding to the shared desktop-auth flow.
struct VncProto;

impl DesktopProtocol for VncProto {
    type Options = TargetVncOptions;
    const NAME: &'static str = PROTOCOL_NAME;
    const LABEL: &'static str = "vnc";

    fn options(target: &Target) -> Option<TargetVncOptions> {
        match &target.options {
            TargetOptions::Vnc(options) => Some(options.clone()),
            _ => None,
        }
    }
}
