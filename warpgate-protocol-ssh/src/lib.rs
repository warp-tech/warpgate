mod channel_audit;
mod client;
mod command_detector;
mod common;
mod keys;
pub mod known_hosts;
mod server;
use std::fmt::Debug;

use anyhow::Result;
pub use channel_audit::ChannelAudit;
pub use client::*;
pub use common::*;
use futures::future::BoxFuture;
pub use keys::*;
pub use server::bind_server;
use warpgate_common::{ListenEndpoint, Protocol};
use warpgate_core::{ProtocolServer, Services};
use warpgate_tls::TlsCertificateAndPrivateKey;

pub const PROTOCOL_NAME: Protocol = Protocol::Ssh;

#[derive(Clone)]
pub struct SSHProtocolServer {
    services: Services,
}

impl SSHProtocolServer {
    pub async fn new(services: &Services) -> Result<Self> {
        let config = services.config.lock().await;
        generate_keys(&config, &services.global_params, "host")?;
        ensure_client_keys(&services.db, &config, &services.global_params).await?;
        Ok(Self {
            services: services.clone(),
        })
    }
}

impl ProtocolServer for SSHProtocolServer {
    async fn bind(
        self,
        address: ListenEndpoint,
        proxy_protocol: bool,
        _tls: Vec<TlsCertificateAndPrivateKey>,
    ) -> Result<BoxFuture<'static, Result<()>>> {
        bind_server(self.services, address, proxy_protocol).await
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
