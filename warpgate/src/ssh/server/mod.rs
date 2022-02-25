use anyhow::Result;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;

mod session;
mod session_handle;
mod thrussh_handler;
pub use session::ServerSession;
pub use thrussh_handler::ServerHandler;

use thrussh::MethodSet;
use thrussh_keys::load_secret_key;
use tokio::sync::Mutex;
use tracing::*;
use warpgate_common::State;

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

            let client = ServerSession::new(remote_address, self.state.clone()).await;
            let id = { client.lock().await.id };

            let handler = ServerHandler {
                id,
                client,
            };

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
