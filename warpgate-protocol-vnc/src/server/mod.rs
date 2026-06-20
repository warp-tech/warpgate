mod rfb;
mod session_handle;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use rustls::ServerConfig;
use rustls::server::NoClientAuth;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, copy_bidirectional};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};
use tokio_rustls::TlsAcceptor;
use tokio_stream::StreamExt;
use tracing::{Instrument, debug, error, info, info_span, warn};
use warpgate_common::auth::{
    AuthCredential, AuthResult, AuthSelector, AuthStateUserInfo, CredentialKind,
};
use warpgate_common::helpers::net::detect_port_knock;
use warpgate_common::{
    ListenEndpoint, Secret, Target, TargetOptions, TargetVncOptions, VncTargetAuth,
};
use warpgate_core::{
    ConfigProvider, Services, SessionStateInit, State, WarpgateServerHandle, authorize_ticket,
    consume_ticket,
};
use warpgate_tls::{
    ResolveServerCert, TlsCertificateAndPrivateKey, TlsCertificateBundle, TlsPrivateKey,
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

/// A viewer connection after its security upgrade: a TLS stream for VeNCrypt, or the
/// raw (rate-limited) stream for Apple-DH. Boxed because those have distinct types and
/// `wrap_stream` returns an opaque one.
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
        authenticate(services, server_handle, &username, password, remote_address).await;

    let (user_info, target, vnc_options) = match authenticated {
        Ok(v) => v,
        Err(error) => {
            warn!(%error, "Authentication failed");
            server_write_security_result(&mut viewer, false, "Authentication failed")
                .await
                .ok();
            return Ok(None);
        }
    };

    server_write_security_result(&mut viewer, true, "").await?;

    {
        let handle = server_handle.lock().await;
        handle.set_user_info(user_info).await?;
        handle.set_target(&target).await?;
    }

    info!(target=%target.name, "Authorized");

    let shared_flag = server_read_client_init(&mut viewer).await?;

    let target_password = match &vnc_options.auth {
        VncTargetAuth::Password(auth) => auth.password.expose_secret().clone(),
        VncTargetAuth::None(_) => String::new(),
    };

    debug!(
        host = %vnc_options.host,
        port = vnc_options.port,
        shared_flag,
        "viewer ready; connecting to backend"
    );

    let mut backend = TcpStream::connect((vnc_options.host.as_str(), vnc_options.port))
        .await
        .context("connecting to VNC target")?;
    backend.set_nodelay(true).ok();

    let server_init = backend_handshake(&mut backend, &target_password, shared_flag).await?;
    debug!(
        len = server_init.len(),
        "backend handshake complete; forwarding ServerInit to viewer"
    );
    viewer.write_all(&server_init).await?;
    viewer.flush().await?;

    Ok(Some((viewer, backend)))
}

async fn authenticate(
    services: &Services,
    server_handle: &Arc<tokio::sync::Mutex<WarpgateServerHandle>>,
    selector: &str,
    password: String,
    remote_address: SocketAddr,
) -> Result<(AuthStateUserInfo, Target, TargetVncOptions)> {
    let selector: AuthSelector = selector.into();

    match selector {
        AuthSelector::User {
            username,
            target_name,
        } => {
            let state_arc = services
                .auth_state_store
                .lock()
                .await
                .create(
                    Some(&server_handle.lock().await.id()),
                    &username,
                    PROTOCOL_NAME,
                    &[CredentialKind::Password],
                    Some(remote_address.ip()),
                )
                .await?
                .1;
            let mut state = state_arc.lock().await;

            {
                let credential = AuthCredential::Password(Secret::new(password));
                let mut cp = services.config_provider.lock().await;
                if cp.validate_credential(&username, &credential).await? {
                    state.add_valid_credential(credential);
                }
            }

            match state.verify() {
                AuthResult::Accepted { user_info } => {
                    services
                        .auth_state_store
                        .lock()
                        .await
                        .complete(state.id())
                        .await;
                    let authorized = services
                        .config_provider
                        .lock()
                        .await
                        .authorize_target(&user_info.username, &target_name)
                        .await?;
                    if !authorized {
                        bail!(
                            "Target {target_name} not authorized for {}",
                            user_info.username
                        );
                    }
                    let (target, options) = find_vnc_target(services, &target_name).await?;
                    Ok((user_info, target, options))
                }
                AuthResult::Rejected | AuthResult::Need(_) => bail!("Authentication rejected"),
            }
        }
        AuthSelector::Ticket { secret } => match authorize_ticket(&services.db, &secret).await? {
            Some((ticket, target_model, user_info)) => {
                consume_ticket(&services.db, &ticket.id).await?;
                let (target, options) = find_vnc_target(services, &target_model.name).await?;
                Ok((user_info, target, options))
            }
            None => bail!("Invalid ticket"),
        },
    }
}

async fn find_vnc_target(
    services: &Services,
    target_name: &str,
) -> Result<(Target, TargetVncOptions)> {
    let targets = services.config_provider.lock().await.list_targets().await?;
    for t in targets {
        if t.name == target_name
            && let TargetOptions::Vnc(ref options) = t.options
        {
            return Ok((t.clone(), options.clone()));
        }
    }
    bail!("VNC target {target_name} not found");
}
