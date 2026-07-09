use std::fmt::Debug;

use anyhow::Result;
use futures::future::BoxFuture;
use warpgate_common::{ListenEndpoint, ProtocolName};
use warpgate_core::{ProtocolServer, Services};
use warpgate_tls::TlsCertificateAndPrivateKey;

mod correlator;
pub mod recording;
mod server;
mod session_handle;
pub use server::bind_server;

pub static PROTOCOL_NAME: ProtocolName = "Kubernetes";

#[derive(Clone)]
pub struct KubernetesProtocolServer {
    services: Services,
}

impl KubernetesProtocolServer {
    pub fn new(services: &Services) -> Self {
        Self {
            services: services.clone(),
        }
    }
}

impl ProtocolServer for KubernetesProtocolServer {
    async fn bind(
        self,
        address: ListenEndpoint,
        proxy_protocol: bool,
        tls: Vec<TlsCertificateAndPrivateKey>,
    ) -> Result<BoxFuture<'static, Result<()>>> {
        bind_server(self.services, address, proxy_protocol, tls).await
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
