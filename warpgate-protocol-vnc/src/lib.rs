use std::fmt::Debug;

use anyhow::{Context, Result};
use futures::future::BoxFuture;
use warpgate_common::{ListenEndpoint, Protocol};
use warpgate_core::{ProtocolServer, Services};
use warpgate_tls::TlsCertificateAndPrivateKey;

mod client;
mod server;

pub use client::connect;
pub use server::bind_server;

pub const PROTOCOL_NAME: Protocol = Protocol::Vnc;

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
        proxy_protocol: bool,
        tls: Vec<TlsCertificateAndPrivateKey>,
    ) -> Result<BoxFuture<'static, Result<()>>> {
        let certificate_and_key = tls
            .into_iter()
            .next()
            .context("VNC requires a TLS certificate and key")?;
        bind_server(self.services, address, proxy_protocol, certificate_and_key).await
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
