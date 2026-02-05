mod client;
mod common;
mod compat;
mod keys;
pub mod known_hosts;
mod server;
use std::fmt::Debug;

use anyhow::Result;
pub use client::*;
pub use common::*;
pub use keys::*;
pub use server::run_server;
use warpgate_common::{ListenEndpoint, ProtocolName};
use warpgate_core::{ProtocolServer, Services};

pub static PROTOCOL_NAME: ProtocolName = "SSH";

#[derive(Clone)]
pub struct SSHProtocolServer {
    services: Services,
}

impl SSHProtocolServer {
    pub async fn new(services: &Services) -> Result<Self> {
        let config = services.config.lock().await;
        generate_keys(&config, &services.global_params, "host")?;
        generate_keys(&config, &services.global_params, "client")?;
        Ok(SSHProtocolServer {
            services: services.clone(),
        })
    }
}

impl ProtocolServer for SSHProtocolServer {
    async fn run(self, address: ListenEndpoint) -> Result<()> {
        run_server(self.services, address).await
    }

    fn name(&self) -> &'static str {
        "SSH"
    }
}

impl Debug for SSHProtocolServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SSHProtocolServer").finish()
    }
}
