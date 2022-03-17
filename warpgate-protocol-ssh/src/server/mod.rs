mod russh_handler;
mod session;
mod session_handle;
use crate::server::session_handle::SSHSessionHandle;
use anyhow::Result;
use russh::MethodSet;
pub use russh_handler::ServerHandler;
use russh_keys::load_secret_key;
pub use session::ServerSession;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::*;
use warpgate_common::{Services, SessionState};

pub async fn run_server(services: Services, address: SocketAddr) -> Result<()> {
    let mut config = russh::server::Config {
        auth_rejection_time: std::time::Duration::from_secs(1),
        methods: MethodSet::PUBLICKEY | MethodSet::PASSWORD,
        ..Default::default()
    };
    config.keys.push(load_secret_key("host_key", None).unwrap());
    config
        .keys
        .push(load_secret_key("/Users/eugene/.ssh/id_rsa", None).unwrap());
    let config = Arc::new(config);

    let socket = TcpListener::bind(&address).await?;
    info!(?address, "Listening");
    while let Ok((socket, remote_address)) = socket.accept().await {
        let config = config.clone();

        let (session_handle, session_handle_rx) = SSHSessionHandle::new();
        let session_state = Arc::new(Mutex::new(SessionState::new(
            remote_address,
            Box::new(session_handle),
        )));

        let server_handle = services
            .state
            .lock()
            .await
            .register_session(&session_state)
            .await?;

        let session = match ServerSession::new(
            remote_address,
            &services,
            server_handle,
            session_handle_rx,
        )
        .await
        {
            Ok(session) => session,
            Err(error) => {
                error!(%error, "Error setting up session");
                continue;
            }
        };

        let id = { session.lock().await.id };

        let handler = ServerHandler { id, session };

        tokio::task::Builder::new()
            .name(&format!("SSH {id} protocol"))
            .spawn(_run_stream(config, socket, handler));
    }
    Ok(())
}

async fn _run_stream<R>(
    config: Arc<russh::server::Config>,
    socket: R,
    handler: ServerHandler,
) -> Result<()>
where
    R: AsyncRead + AsyncWrite + Unpin + Debug,
{
    russh::server::run_stream(config, socket, handler).await?;
    Ok(())
}
