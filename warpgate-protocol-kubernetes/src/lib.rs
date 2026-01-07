mod client;
mod correlator;
pub mod recording;
mod server;
mod session_handle;

use std::fmt::Debug;

use anyhow::Result;
pub use client::*;
pub use server::run_server;
use warpgate_common::{
    ListenEndpoint, ProtocolName, Target, TargetKubernetesOptions, TargetOptions,
};
use warpgate_core::{ProtocolServer, Services, TargetTestError};

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

    async fn test_target(&self, target: Target) -> Result<(), TargetTestError> {
        let TargetOptions::Kubernetes(options) = &target.options else {
            return Err(TargetTestError::Misconfigured(
                "Not a Kubernetes target".to_string(),
            ));
        };

        test_kubernetes_target(options.clone()).await
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

async fn test_kubernetes_target(options: TargetKubernetesOptions) -> Result<(), TargetTestError> {
    // Test connection to Kubernetes cluster
    match client::test_connection(&options).await {
        Ok(_) => Ok(()),
        Err(e) => {
            if e.to_string().contains("authentication") || e.to_string().contains("Unauthorized") {
                Err(TargetTestError::AuthenticationError)
            } else if e.to_string().contains("connection") || e.to_string().contains("unreachable")
            {
                Err(TargetTestError::Unreachable)
            } else {
                Err(TargetTestError::ConnectionError(e.to_string()))
            }
        }
    }
}
