mod kubernetes;
mod openstack;
mod shell;

use std::fmt::Debug;

use anyhow::Result;
use warpgate_common::{
    ListenEndpoint, ProtocolName, Target, TargetOptions, TargetRemoteRunOptions,
};
use warpgate_core::{ProtocolServer, Services, TargetTestError};

pub static PROTOCOL_NAME: ProtocolName = "RemoteRun";

/// Protocol server for RemoteRun targets.
/// Unlike other protocols, RemoteRun doesn't listen on a socket.
/// Sessions are triggered via SSH subsystem commands or HTTP API endpoints.
#[derive(Clone)]
pub struct RemoteRunProtocolServer {
    services: Services,
}

impl RemoteRunProtocolServer {
    pub async fn new(services: &Services) -> Result<Self> {
        Ok(Self {
            services: services.clone(),
        })
    }

    /// Execute a RemoteRun session for the given target.
    /// This is called when a user connects via SSH subsystem or HTTP API.
    pub async fn execute_session(&self, target: &Target) -> Result<()> {
        let TargetOptions::RemoteRun(ref options) = target.options else {
            anyhow::bail!("Not a RemoteRun target");
        };

        match options {
            TargetRemoteRunOptions::Shell(opts) => {
                shell::execute(&self.services, opts).await
            }
            TargetRemoteRunOptions::OpenStack(opts) => {
                openstack::execute(&self.services, opts).await
            }
            TargetRemoteRunOptions::Kubernetes(opts) => {
                kubernetes::execute(&self.services, opts).await
            }
        }
    }
}

impl ProtocolServer for RemoteRunProtocolServer {
    /// RemoteRun doesn't listen on a socket; sessions are triggered via other protocols.
    async fn run(self, _address: ListenEndpoint) -> Result<()> {
        // No-op: RemoteRun sessions are initiated through SSH subsystem or HTTP API
        tracing::info!("RemoteRun protocol server initialized (no listening socket)");
        // Keep the future alive indefinitely
        futures::future::pending::<()>().await;
        Ok(())
    }

    async fn test_target(&self, target: Target) -> Result<(), TargetTestError> {
        let TargetOptions::RemoteRun(options) = target.options else {
            return Err(TargetTestError::Misconfigured(
                "Not a RemoteRun target".to_owned(),
            ));
        };

        match options {
            TargetRemoteRunOptions::Shell(opts) => {
                shell::test_connection(&opts)
                    .await
                    .map_err(|e| TargetTestError::ConnectionError(e.to_string()))
            }
            TargetRemoteRunOptions::OpenStack(opts) => {
                openstack::test_connection(&opts)
                    .await
                    .map_err(|e| TargetTestError::ConnectionError(e.to_string()))
            }
            TargetRemoteRunOptions::Kubernetes(opts) => {
                kubernetes::test_connection(&opts)
                    .await
                    .map_err(|e| TargetTestError::ConnectionError(e.to_string()))
            }
        }
    }

    fn name(&self) -> &'static str {
        PROTOCOL_NAME
    }
}

impl Debug for RemoteRunProtocolServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RemoteRunProtocolServer")
    }
}
