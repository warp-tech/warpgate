use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::{SocketAddr};
use std::sync::Arc;
use tokio::net::TcpListener;

mod handler;
mod session;
pub use handler::ServerHandler;
pub use session::ServerSession;

use crate::misc::Client;
use thrussh::MethodSet;
use thrussh_keys::load_secret_key;
use tokio::sync::Mutex;
use tracing::*;

#[derive(Clone)]
pub struct SSHProtocolServer {
    clients: Arc<Mutex<HashMap<u64, Client>>>,
    last_client_id: u64,
}

impl SSHProtocolServer {
    pub fn new() -> Self {
        SSHProtocolServer {
            clients: Arc::new(Mutex::new(HashMap::new())),
            last_client_id: 0,
        }
    }

    pub async fn run(mut self, address: SocketAddr) -> Result<()> {
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

            self.last_client_id += 1;
            let client =
                ServerSession::new(self.clients.clone(), self.last_client_id, remote_address);
            let handler = ServerHandler { id: self.last_client_id, client };

            tokio::task::Builder::new()
                .name(&format!("SSH S{} protocol", self.last_client_id))
                .spawn(_run_stream(self.last_client_id, config, socket, handler));
        }
        Ok(())
    }
}

async fn _run_stream<R>(
    id: u64,
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
