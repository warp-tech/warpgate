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
use futures::future::BoxFuture;
pub use keys::*;
pub use server::bind_server;
use warpgate_common::{ListenEndpoint, ProtocolName};
use warpgate_core::{ProtocolServer, Services};
use warpgate_tls::TlsCertificateAndPrivateKey;

pub static PROTOCOL_NAME: ProtocolName = "SSH";

#[derive(Clone)]
pub struct SSHProtocolServer {
    services: Services,
}

impl SSHProtocolServer {
    pub async fn new(services: &Services) -> Result<Self> {
        let config = services.config.lock().await;
        ensure_keys(&config, &services.global_params, &*services.secret_backend, "host").await?;
        ensure_keys(
            &config,
            &services.global_params,
            &*services.secret_backend,
            "client",
        )
        .await?;
        Ok(Self {
            services: services.clone(),
        })
    }
}

impl ProtocolServer for SSHProtocolServer {
    async fn bind(
        self,
        address: ListenEndpoint,
        _tls: Vec<TlsCertificateAndPrivateKey>,
    ) -> Result<BoxFuture<'static, Result<()>>> {
        bind_server(self.services, address).await
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
