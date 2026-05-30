use std::fmt::Debug;

use anyhow::Result;
use warpgate_common::{ListenEndpoint, ProtocolName};
use warpgate_core::{ProtocolServer, Services};

mod client;
mod server;

pub use client::{VncClientHandles, connect};
pub use server::run_server;

pub static PROTOCOL_NAME: ProtocolName = "VNC";

pub struct VncProtocolServer {
    services: Services,
}

impl VncProtocolServer {
    pub fn new(services: &Services) -> Self {
        Self {
            services: services.clone(),
        }
    }
}

impl ProtocolServer for VncProtocolServer {
    async fn run(self, address: ListenEndpoint) -> Result<()> {
        run_server(self.services, address).await
    }

    fn name(&self) -> &'static str {
        "VNC"
    }
}

impl Debug for VncProtocolServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VncProtocolServer").finish()
    }
}
