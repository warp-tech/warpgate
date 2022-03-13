use anyhow::Result;
use async_trait::async_trait;
use russh::MethodSet;
use russh_keys::load_secret_key;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::*;

mod russh_handler;
mod session;
mod session_handle;
pub use russh_handler::ServerHandler;
pub use session::ServerSession;

use crate::server::session_handle::SSHSessionHandle;
use warpgate_common::{ProtocolServer, Services, SessionState};

#[derive(Clone)]
pub struct SSHProtocolServer {
    services: Services,
}

impl SSHProtocolServer {
    pub fn new(services: &Services) -> Self {
        SSHProtocolServer {
            services: services.clone(),
        }
    }
}

#[async_trait]
impl ProtocolServer for SSHProtocolServer {
    async fn run(self, address: SocketAddr) -> Result<()> {
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
        info!("Starting server on {address}");
        while let Ok((socket, remote_address)) = socket.accept().await {
            let config = config.clone();

            let (session_handle, session_handle_rx) = SSHSessionHandle::new();
            let session_state = Arc::new(Mutex::new(SessionState::new(
                remote_address,
                Box::new(session_handle),
            )));

            let server_handle = self
                .services
                .state
                .lock()
                .await
                .register_session(&session_state)
                .await?;

            let session = match ServerSession::new(
                remote_address,
                &self.services,
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

impl Debug for SSHProtocolServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SSHProtocolServer")
    }
}
