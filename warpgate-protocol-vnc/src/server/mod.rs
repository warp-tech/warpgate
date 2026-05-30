mod rfb;
mod session_handle;

use std::sync::Arc;
use std::net::SocketAddr;

use anyhow::{Context, Result, bail};
use futures::TryStreamExt;
use rustls::ServerConfig;
use rustls::server::NoClientAuth;
use tokio::io::{AsyncWriteExt, copy_bidirectional};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{Instrument, error, info, info_span, warn};
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
    backend_handshake, server_read_client_init, server_read_plain_credentials,
    server_vencrypt_pre_tls, server_write_security_result,
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
                    format!("reading TLS certificate from '{}'", certificate_path.display())
                })?,
            private_key: TlsPrivateKey::from_file(&key_path)
                .await
                .with_context(|| format!("reading TLS private key from '{}'", key_path.display()))?,
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

    loop {
        let Some(stream) = listener.try_next().await.context("accepting connection")? else {
            return Ok(());
        };
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
}

async fn handle_connection(
    services: Services,
    server_handle: Arc<tokio::sync::Mutex<WarpgateServerHandle>>,
    stream: TcpStream,
    tls_config: Arc<ServerConfig>,
    remote_address: SocketAddr,
) -> Result<()> {
    let mut stream = {
        let guard = server_handle.lock().await;
        guard.wrap_stream(stream).await?
    };

    // Plaintext VeNCrypt negotiation, then TLS upgrade.
    server_vencrypt_pre_tls(&mut stream).await?;
    let acceptor = TlsAcceptor::from(tls_config);
    let mut tls = acceptor.accept(stream).await.context("TLS handshake")?;

    // VeNCrypt Plain credentials over TLS.
    let (username, password) = server_read_plain_credentials(&mut tls).await?;

    let authenticated = authenticate(
        &services,
        &server_handle,
        &username,
        password,
        remote_address,
    )
    .await;

    let (user_info, target, vnc_options) = match authenticated {
        Ok(v) => v,
        Err(error) => {
            warn!(%error, "Authentication failed");
            server_write_security_result(&mut tls, false, "Authentication failed")
                .await
                .ok();
            return Ok(());
        }
    };

    server_write_security_result(&mut tls, true, "").await?;

    {
        let handle = server_handle.lock().await;
        handle.set_user_info(user_info).await?;
        handle.set_target(&target).await?;
    }

    info!(target=%target.name, "Authorized");

    let shared_flag = server_read_client_init(&mut tls).await?;

    let target_password = match &vnc_options.auth {
        VncTargetAuth::Password(auth) => auth.password.expose_secret().clone(),
        VncTargetAuth::None(_) => String::new(),
    };

    let mut backend = TcpStream::connect((vnc_options.host.as_str(), vnc_options.port))
        .await
        .context("connecting to VNC target")?;
    backend.set_nodelay(true).ok();

    let server_init = backend_handshake(&mut backend, &target_password, shared_flag).await?;
    tls.write_all(&server_init).await?;
    tls.flush().await?;

    // Transparent relay between the (TLS) viewer and the backend target.
    copy_bidirectional(&mut tls, &mut backend)
        .await
        .context("relaying VNC session")?;

    Ok(())
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
                        bail!("Target {target_name} not authorized for {}", user_info.username);
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
        if t.name == target_name {
            if let TargetOptions::Vnc(ref options) = t.options {
                return Ok((t.clone(), options.clone()));
            }
        }
    }
    bail!("VNC target {target_name} not found");
}
