use std::fmt::Debug;

use anyhow::{Context, Result};
use futures::future::BoxFuture;
use warpgate_common::{ListenEndpoint, ProtocolName};
use warpgate_core::{ProtocolServer, Services};
use warpgate_tls::TlsCertificateAndPrivateKey;

mod client;
mod server;

pub use client::{VncClientHandles, connect};
pub use server::bind_server;

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
    async fn bind(
        self,
        address: ListenEndpoint,
        tls: Vec<TlsCertificateAndPrivateKey>,
    ) -> Result<BoxFuture<'static, Result<()>>> {
        let certificate_and_key = tls
            .into_iter()
            .next()
            .context("VNC requires a TLS certificate and key")?;
        bind_server(self.services, address, certificate_and_key).await
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
