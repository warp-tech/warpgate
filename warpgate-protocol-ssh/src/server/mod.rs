mod channel_registry;
mod channel_writer;
mod event_intake;
mod russh_handler;
mod service_output;
mod session;
mod session_handle;
mod target_menu;
mod transport_abort;

use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use futures::FutureExt;
use futures::future::BoxFuture;
use russh::keys::{Algorithm, HashAlg, PrivateKey};
use russh::{MethodKind, MethodSet, Preferred};
pub use russh_handler::ServerHandler;
pub use session::ServerSession;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc::unbounded_channel;
use tokio::sync::oneshot;
use tracing::*;
use transport_abort::AbortableStream;
use warpgate_common::ListenEndpoint;
use warpgate_common::helpers::net::accept_loop;
use warpgate_core::{Services, State, UserSessionStateInit};
use warpgate_db_entities::Parameters;

use crate::keys::load_keys;
use crate::server::session_handle::SSHSessionHandle;

#[derive(Clone)]
struct RusshConfigInit {
    keys: Vec<PrivateKey>,
}

pub async fn bind_server(
    services: Services,
    address: ListenEndpoint,
    proxy_protocol: bool,
) -> Result<BoxFuture<'static, Result<()>>> {
    let russh_config_init = Arc::new({
        let config = services.config.lock().await;
        RusshConfigInit {
            keys: load_keys(&config, &services.global_params, "host")?,
        }
    });

    let listener = address.tcp_accept_stream().await?;

    Ok(async move {
        accept_loop(
            "SSH connection",
            listener,
            proxy_protocol,
            move |stream, remote_address| {
                let russh_config_init = russh_config_init.clone();
                let services = services.clone();
                async move {
                    _handle_connection(services, russh_config_init, stream, remote_address).await
                }
            },
        )
        .await;
        Ok(())
    }
    .boxed())
}

async fn _handle_connection(
    services: Services,
    russh_config_init: Arc<RusshConfigInit>,
    stream: TcpStream,
    remote_address: SocketAddr,
) -> Result<()> {
    let (session_handle, session_handle_rx) = SSHSessionHandle::new();

    let (server_handle, wrapped_stream) = State::register_user_session_with_stream(
        &services.state,
        crate::PROTOCOL_NAME,
        UserSessionStateInit {
            remote_address: Some(remote_address),
            handle: Box::new(session_handle),
        },
        stream,
    )
    .await
    .context("registering session")?;

    // The last resort for a client that has stopped reading. See
    // `transport_abort`.
    let (wrapped_stream, transport_abort) = AbortableStream::new(wrapped_stream);

    let id = server_handle.lock().await.user_session_id();

    let (event_tx, event_rx) = unbounded_channel();

    let banner = {
        let db = &services.db;
        // Normalize line endings for terminal display.
        Parameters::Entity::get(db)
            .await?
            .banner_text()
            .map(|text| format!("{}\r\n", text.replace("\r\n", "\n").replace('\n', "\r\n")))
    };

    let handler = ServerHandler { event_tx, banner };

    // The only link between the session and the wire protocol tasks: it lets
    // a teardown find out when russh's loop has actually shut the stream
    // down, instead of guessing with a sleep (#2520).
    let (protocol_done_tx, protocol_done_rx) = oneshot::channel();

    let session = match ServerSession::start(
        remote_address,
        &services,
        server_handle,
        session_handle_rx,
        event_rx,
        protocol_done_rx,
        transport_abort,
    )
    .await
    {
        Ok(session) => session,
        Err(error) => {
            error!(%error, "Error setting up session");
            return Err(error);
        }
    };

    let russh_config = {
        let config = services.config.lock().await;

        russh::server::Config {
            auth_rejection_time: Duration::from_secs(1),
            auth_rejection_time_initial: Some(Duration::from_secs(0)),
            // Extra time for the "closing due to inactivity" message to be sent
            inactivity_timeout: Some(config.store.ssh.inactivity_timeout + Duration::from_secs(10)),
            keepalive_interval: config.store.ssh.keepalive_interval,
            methods: get_allowed_auth_methods(&services).await?,
            keys: russh_config_init.keys.clone(),
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

    tokio::task::Builder::new()
        .name(&format!("SSH {id} session"))
        .spawn(session)?;

    tokio::task::Builder::new()
        .name(&format!("SSH {id} protocol"))
        .spawn(_run_stream(
            russh_config,
            wrapped_stream,
            handler,
            protocol_done_tx,
        ))?;

    Ok(())
}

async fn _run_stream<R>(
    config: Arc<russh::server::Config>,
    socket: R,
    handler: ServerHandler,
    protocol_done_tx: oneshot::Sender<()>,
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

    // Sent on both outcomes: the session side only cares that this task is
    // done, not why. A dropped receiver makes it a no-op.
    let _ = protocol_done_tx.send(());

    if let Err(ref error) = ret {
        error!(%error, "Session failed");
    }

    ret
}

pub async fn get_allowed_auth_methods(services: &Services) -> Result<MethodSet> {
    let parameters = {
        let db = &services.db;
        Parameters::Entity::get(db).await?
    };

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

    if methods_vec.is_empty() {
        warn!(
            "All SSH authentication methods are disabled in parameters. Enabling all methods as fallback."
        );
        methods_vec = vec![
            MethodKind::PublicKey,
            MethodKind::Password,
            MethodKind::KeyboardInteractive,
        ];
    }

    Ok(MethodSet::from(&methods_vec[..]))
}
