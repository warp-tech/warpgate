mod channel_writer;
mod russh_handler;
mod service_output;
mod session;
mod session_handle;
use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use futures::TryStreamExt;
use russh::keys::{Algorithm, HashAlg};
use russh::{MethodKind, MethodSet, Preferred};
pub use russh_handler::ServerHandler;
pub use session::ServerSession;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc::unbounded_channel;
use tracing::*;
use warpgate_common::ListenEndpoint;
use warpgate_core::{Services, SessionStateInit, State};
use warpgate_db_entities::Parameters;

use crate::keys::load_keys;
use crate::server::session_handle::SSHSessionHandle;

pub async fn run_server(services: Services, address: ListenEndpoint) -> Result<()> {
    let russh_config = {
        let config = services.config.lock().await;
        
        // Fetch SSH auth method settings from Parameters
        let db = services.db.lock().await;
        let parameters = Parameters::Entity::get(&db).await?;
        drop(db);
        
        // Build MethodSet based on parameters
        let mut methods_vec: Vec<MethodKind> = Vec::new();
        if parameters.ssh_client_auth_publickey {
            methods_vec.push(MethodKind::PublicKey);
        }
        if parameters.ssh_client_auth_password {
            methods_vec.push(MethodKind::Password);
        }
        if parameters.ssh_client_auth_keyboard_interactive {
            methods_vec.push(MethodKind::KeyboardInteractive);
        }
        
        // Ensure at least one method is enabled, fall back to all if none
        if methods_vec.is_empty() {
            warn!("All SSH authentication methods are disabled in parameters. Enabling all methods as fallback.");
            methods_vec = vec![
                MethodKind::PublicKey,
                MethodKind::Password,
                MethodKind::KeyboardInteractive,
            ];
        }
        
        info!(
            "SSH server authentication methods: publickey={}, password={}, keyboard-interactive={}",
            parameters.ssh_client_auth_publickey,
            parameters.ssh_client_auth_password,
            parameters.ssh_client_auth_keyboard_interactive
        );
        
        russh::server::Config {
            auth_rejection_time: Duration::from_secs(1),
            auth_rejection_time_initial: Some(Duration::from_secs(0)),
            inactivity_timeout: Some(config.store.ssh.inactivity_timeout),
            keepalive_interval: config.store.ssh.keepalive_interval,
            methods: MethodSet::from(&methods_vec[..]),
            keys: load_keys(&config, &services.global_params, "host")?,
            event_buffer_size: 100,
            nodelay: true,
            preferred: Preferred {
                key: Cow::Borrowed(&[
                    Algorithm::Ed25519,
                    Algorithm::Rsa {
                        hash: Some(HashAlg::Sha512),
                    },
                    Algorithm::Rsa {
                        hash: Some(HashAlg::Sha256),
                    },
                    Algorithm::Rsa { hash: None },
                ]),
                ..<_>::default()
            },
            ..<_>::default()
        }
    };

    let russh_config = Arc::new(russh_config);

    let mut listener = address.tcp_accept_stream().await?;

    while let Some(stream) = listener.try_next().await.context("accepting connection")? {
        let russh_config = russh_config.clone();
        let services = services.clone();

        tokio::task::Builder::new()
            .name("SSH new connection setup")
            .spawn(async move {
                if let Err(e) = _handle_connection(services, russh_config, stream).await {
                    error!(%e, "Connection handling failed");
                }
            })?;
    }
    Ok(())
}

async fn _handle_connection(
    services: Services,
    russh_config: Arc<russh::server::Config>,
    stream: TcpStream,
) -> Result<()> {
    stream.set_nodelay(true)?;

    let remote_address = stream.peer_addr().context("getting peer address")?;

    let (session_handle, session_handle_rx) = SSHSessionHandle::new();

    let server_handle = State::register_session(
        &services.state,
        &crate::PROTOCOL_NAME,
        SessionStateInit {
            remote_address: Some(remote_address),
            handle: Box::new(session_handle),
        },
    )
    .await
    .context("registering session")?;

    let id = server_handle.lock().await.id();

    let (event_tx, event_rx) = unbounded_channel();

    let handler = ServerHandler { event_tx };
    let wrapped_stream = server_handle.lock().await.wrap_stream(stream).await?;

    let session = match ServerSession::start(
        remote_address,
        &services,
        server_handle,
        session_handle_rx,
        event_rx,
    )
    .await
    {
        Ok(session) => session,
        Err(error) => {
            error!(%error, "Error setting up session");
            return Err(error);
        }
    };

    tokio::task::Builder::new()
        .name(&format!("SSH {id} session"))
        .spawn(session)?;

    tokio::task::Builder::new()
        .name(&format!("SSH {id} protocol"))
        .spawn(_run_stream(russh_config, wrapped_stream, handler))?;

    Ok(())
}

async fn _run_stream<R>(
    config: Arc<russh::server::Config>,
    socket: R,
    handler: ServerHandler,
) -> Result<()>
where
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let ret = async move {
        let session = russh::server::run_stream(config, socket, handler).await?;
        session.await?;
        Ok(())
    }
    .await;

    if let Err(ref error) = ret {
        error!(%error, "Session failed");
    }

    ret
}
