mod channel_writer;
mod russh_handler;
mod service_output;
mod session;
mod session_handle;
use std::borrow::Cow;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use futures::TryStreamExt;
use russh::keys::{Algorithm, HashAlg};
use russh::{MethodKind, MethodSet, Preferred};
pub use russh_handler::ServerHandler;
pub use session::ServerSession;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc::unbounded_channel;
use tracing::*;
use warpgate_common::ListenEndpoint;
use warpgate_core::{Services, SessionStateInit};

use crate::keys::load_host_keys;
use crate::server::session_handle::SSHSessionHandle;

pub async fn run_server(services: Services, address: ListenEndpoint) -> Result<()> {
    let russh_config = {
        let config = services.config.lock().await;
        russh::server::Config {
            auth_rejection_time: Duration::from_secs(1),
            auth_rejection_time_initial: Some(Duration::from_secs(0)),
            inactivity_timeout: Some(config.store.ssh.inactivity_timeout),
            keepalive_interval: config.store.ssh.keepalive_interval,
            methods: MethodSet::from(
                &[
                    MethodKind::PublicKey,
                    MethodKind::Password,
                    MethodKind::KeyboardInteractive,
                ][..],
            ),
            keys: vec![load_host_keys(&config)?],
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
        let remote_address = stream.peer_addr().context("getting peer address")?;
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
            .await
            .context("registering session")?;

        let id = server_handle.lock().await.id();

        let (event_tx, event_rx) = unbounded_channel();

        let handler = ServerHandler { event_tx };

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
            .spawn(session)?;

        tokio::task::Builder::new()
            .name(&format!("SSH {id} protocol"))
            .spawn(_run_stream(russh_config, stream, handler))?;
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
