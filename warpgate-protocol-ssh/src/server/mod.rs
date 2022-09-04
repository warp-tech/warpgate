mod channel_writer;
mod russh_handler;
mod service_output;
mod session;
mod session_handle;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use russh::{MethodSet, Preferred};
pub use russh_handler::ServerHandler;
pub use session::ServerSession;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::mpsc::unbounded_channel;
use tracing::*;
use warpgate_core::{Services, SessionStateInit};

use crate::keys::load_host_keys;
use crate::server::session_handle::SSHSessionHandle;

pub async fn run_server(services: Services, address: SocketAddr) -> Result<()> {
    let russh_config = {
        let config = services.config.lock().await;
        russh::server::Config {
            auth_rejection_time: std::time::Duration::from_secs(1),
            connection_timeout: Some(std::time::Duration::from_secs(300)),
            methods: MethodSet::PUBLICKEY | MethodSet::PASSWORD | MethodSet::KEYBOARD_INTERACTIVE,
            keys: load_host_keys(&config)?,
            preferred: Preferred {
                key: &[
                    russh_keys::key::ED25519,
                    russh_keys::key::RSA_SHA2_256,
                    russh_keys::key::RSA_SHA2_512,
                    russh_keys::key::SSH_RSA,
                ],
                ..<_>::default()
            },
            ..<_>::default()
        }
    };

    let russh_config = Arc::new(russh_config);

    let socket = TcpListener::bind(&address).await?;
    info!(?address, "Listening");
    while let Ok((socket, remote_address)) = socket.accept().await {
        let russh_config = russh_config.clone();

        let (session_handle, session_handle_rx) = SSHSessionHandle::new();

        let server_handle = services
            .state
            .lock()
            .await
            .register_session(
                &crate::PROTOCOL_NAME,
                SessionStateInit {
                    remote_address: Some(remote_address),
                    handle: Box::new(session_handle),
                },
            )
            .await?;

        let id = server_handle.lock().await.id();

        let (event_tx, event_rx) = unbounded_channel();

        let handler = ServerHandler { id, event_tx };

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
                continue;
            }
        };

        tokio::task::Builder::new()
            .name(&format!("SSH {id} session"))
            .spawn(session);

        tokio::task::Builder::new()
            .name(&format!("SSH {id} protocol"))
            .spawn(_run_stream(russh_config, socket, handler));
    }
    Ok(())
}

async fn _run_stream<R>(
    config: Arc<russh::server::Config>,
    socket: R,
    handler: ServerHandler,
) -> Result<()>
where
    R: AsyncRead + AsyncWrite + Unpin + Debug + Send + 'static,
{
    let session = russh::server::run_stream(config, socket, handler).await?;
    session.await?;
    Ok(())
}
