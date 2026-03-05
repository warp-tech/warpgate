use std::fmt::Debug;

use anyhow::Result;
use warpgate_common::{ListenEndpoint, ProtocolName};
use warpgate_core::{ProtocolServer, Services};

mod correlator;
pub mod recording;
mod server;
mod session_handle;
pub use server::run_server;

pub static PROTOCOL_NAME: ProtocolName = "Kubernetes";

#[derive(Clone)]
pub struct KubernetesProtocolServer {
    services: Services,
}

impl KubernetesProtocolServer {
    pub async fn new(services: &Services) -> Result<Self> {
        Ok(Self {
            services: services.clone(),
        })
    }
}

impl ProtocolServer for KubernetesProtocolServer {
    async fn run(self, address: ListenEndpoint) -> Result<()> {
        run_server(self.services, address).await
    }

    fn name(&self) -> &'static str {
        "Kubernetes"
    }
}

impl Debug for KubernetesProtocolServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubernetesProtocolServer").finish()
    }
}
