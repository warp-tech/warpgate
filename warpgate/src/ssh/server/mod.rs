use anyhow::Result;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;
use thrussh::MethodSet;
use thrussh_keys::load_secret_key;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::*;

mod session;
mod session_handle;
mod thrussh_handler;
pub use session::ServerSession;
pub use thrussh_handler::ServerHandler;

use crate::ssh::server::session_handle::SSHSessionHandle;
use warpgate_common::{SessionState, State, WarpgateServerHandle};

#[derive(Clone)]
pub struct SSHProtocolServer {
    state: Arc<Mutex<State>>,
}

impl SSHProtocolServer {
    pub fn new(state: Arc<Mutex<State>>) -> Self {
        SSHProtocolServer { state }
    }

    pub async fn run(self, address: SocketAddr) -> Result<()> {
        let mut config = thrussh::server::Config {
            auth_rejection_time: std::time::Duration::from_secs(1),
            methods: MethodSet::PUBLICKEY,
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
            let id = self
                .state
                .lock()
                .await
                .register_session(&session_state)
                .await?;
            let server_handle = WarpgateServerHandle::new(id, self.state.clone(), session_state);

            let session = match ServerSession::new(
                remote_address,
                self.state.clone(),
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
    config: Arc<thrussh::server::Config>,
    socket: R,
    handler: ServerHandler,
) -> Result<()>
where
    R: AsyncRead + AsyncWrite + Unpin + Debug,
{
    thrussh::server::run_stream(config, socket, handler).await?;
    Ok(())
}

impl Debug for SSHProtocolServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SSHProtocolServer")
    }
}
