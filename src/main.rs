#![feature(type_alias_impl_trait)]

use std::collections::HashMap;
use std::sync::Arc;

use misc::Client;
use server_client::ServerClient;
use server_handler::ServerHandler;
use thrussh::MethodSet;
use thrussh_keys::load_secret_key;
use tokio::sync::Mutex;

mod misc;
mod remote_client;
mod server_client;
mod server_handler;


#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[tokio::main]
async fn main() {
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    let server_key = load_secret_key("host_key", None).unwrap();
    let mut config = thrussh::server::Config {
        auth_rejection_time: std::time::Duration::from_secs(1),
        methods: MethodSet::PUBLICKEY,
        ..Default::default()
    };
    config.keys.push(server_key);
    let config = Arc::new(config);
    let sh = Server {
        clients: Arc::new(Mutex::new(HashMap::new())),
        last_client_id: 0,
    };
    thrussh::server::run(config, "0.0.0.0:2222", sh)
        .await
        .unwrap();
}

#[derive(Clone)]
struct Server {
    clients: Arc<Mutex<HashMap<u64, Client>>>,
    last_client_id: u64,
}

impl thrussh::server::Server for Server {
    type Handler = ServerHandler;
    fn new(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
        self.last_client_id += 1;
        let client = ServerClient::new(self.clients.clone(), self.last_client_id);
        ServerHandler {
            client,
        }
    }
}
