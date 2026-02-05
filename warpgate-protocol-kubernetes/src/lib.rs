use std::fmt::Debug;

use anyhow::Result;
use warpgate_common::{ListenEndpoint, ProtocolName, Target};
use warpgate_core::{ProtocolServer, Services, TargetTestError};

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

    async fn test_target(&self, _target: Target) -> Result<(), TargetTestError> {
        Err(TargetTestError::Misconfigured(
            "Testing Kubernetes targets is not implemented yet".into(),
        ))
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
