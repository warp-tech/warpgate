mod protocol;
mod rfb;
mod session_handle;

use std::collections::HashSet;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
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
use warpgate_core::{
    ConfigProvider, Services, SessionStateInit, State, WarpgateServerHandle, authorize_ticket,
    consume_ticket,
};
use warpgate_protocol_vnc_ui as ui;
use warpgate_tls::{
    ResolveServerCert, TlsCertificateAndPrivateKey, TlsCertificateBundle, TlsPrivateKey,
};

use self::protocol::{
    ClientEvent, DEFAULT_PIXEL_FORMAT, PixelFormat, forward_format_setup, pack_rgb,
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

pub async fn run_server(services: Services, address: ListenEndpoint) -> Result<()> {
    let certificate_and_key = {
        let config = services.config.lock().await;
        let paths_rel_to = services.global_params.paths_relative_to();
        let certificate_path = paths_rel_to.join(&config.store.vnc.certificate);
        let key_path = paths_rel_to.join(&config.store.vnc.key);

        TlsCertificateAndPrivateKey {
            certificate: TlsCertificateBundle::from_file(&certificate_path)
                .await
                .with_context(|| {
                    format!(
                        "reading TLS certificate from '{}'",
                        certificate_path.display()
                    )
                })?,
            private_key: TlsPrivateKey::from_file(&key_path).await.with_context(|| {
                format!("reading TLS private key from '{}'", key_path.display())
            })?,
        }
    };

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

    while let Some(stream) = listener.next().await {
        let remote_address = stream.peer_addr().context("getting peer address")?;
        stream.set_nodelay(true)?;
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
    let Some((mut viewer, mut backend)) = timeout_at(
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

    debug!("starting bidirectional relay");
    copy_bidirectional(&mut viewer, &mut backend)
        .await
        .context("relaying VNC session")?;

    Ok(())
}

/// Negotiate security, authenticate the viewer, and connect + handshake the backend
async fn negotiate_and_authorize(
    mut stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    services: &Services,
    server_handle: &Arc<tokio::sync::Mutex<WarpgateServerHandle>>,
    tls_config: Arc<ServerConfig>,
    remote_address: SocketAddr,
) -> Result<Option<(Box<dyn ViewerStream>, TcpStream)>> {
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
            (user_info, target, options)
        }
    };

    {
        let handle = server_handle.lock().await;
        handle.set_user_info(user_info).await?;
        handle.set_target(&target).await?;
    }

    info!(target=%target.name, "Authorized");

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

    Ok(Some((viewer, backend)))
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
            Some(ClientEvent::Key { .. }) => {}
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
                        if handle_otp_keypress(keysym, &mut otp, services, &state, username).await {
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
        let valid = services
            .config_provider
            .lock()
            .await
            .validate_credential(username, &credential)
            .await
            .unwrap_or(false);
        if valid {
            state.lock().await.add_valid_credential(credential);
        } else {
            warn!("Incorrect one-time password");
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
                )
                .await?;

            // Password is mandatory, we don't want to serve an anon session
            {
                let credential = AuthCredential::Password(Secret::new(password));
                let mut cp = services.config_provider.lock().await;
                if !cp.validate_credential(&username, &credential).await? {
                    return Ok(None);
                }
                state_arc.lock().await.add_valid_credential(credential);
            }

            let result = state_arc.lock().await.verify();
            match result {
                AuthResult::Accepted { user_info } => {
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
