mod client;
mod common;
mod error;
mod session;
mod session_handle;
mod stream;
use std::fmt::Debug;
use std::sync::Arc;

use anyhow::{Context, Result};
use client::{ConnectionOptions, MySqlClient};
use futures::TryStreamExt;
use rustls::server::NoClientAuth;
use rustls::ServerConfig;
use tracing::*;
use warpgate_common::{ListenEndpoint, Target, TargetOptions};
use warpgate_core::{ProtocolServer, Services, SessionStateInit, State, TargetTestError};
use warpgate_tls::{
    ResolveServerCert, TlsCertificateAndPrivateKey, TlsCertificateBundle, TlsPrivateKey,
};

use crate::session::MySqlSession;
use crate::session_handle::MySqlSessionHandle;

pub struct MySQLProtocolServer {
    services: Services,
}

impl MySQLProtocolServer {
    pub async fn new(services: &Services) -> Result<Self> {
        Ok(MySQLProtocolServer {
            services: services.clone(),
        })
    }
}

impl ProtocolServer for MySQLProtocolServer {
    async fn run(self, address: ListenEndpoint) -> Result<()> {
        let certificate_and_key = {
            let config = self.services.config.lock().await;
            let paths_rel_to = self.services.global_params.paths_relative_to();
            let certificate_path = paths_rel_to.join(&config.store.mysql.certificate);
            let key_path = paths_rel_to.join(&config.store.mysql.key);

            TlsCertificateAndPrivateKey {
                certificate: TlsCertificateBundle::from_file(&certificate_path)
                    .await
                    .with_context(|| {
                        format!("reading SSL private key from '{}'", key_path.display())
                    })?,
                private_key: TlsPrivateKey::from_file(&key_path).await.with_context(|| {
                    format!(
                        "reading SSL certificate from '{}'",
                        certificate_path.display()
                    )
                })?,
            }
        };

        let tls_config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(Arc::new(NoClientAuth))
        .with_cert_resolver(Arc::new(ResolveServerCert(Arc::new(
            certificate_and_key.into(),
        ))));

        let mut listener = address.tcp_accept_stream().await?;

        loop {
            let Some(stream) = listener.try_next().await.context("accepting connection")? else {
                return Ok(());
            };
            let remote_address = stream.peer_addr().context("getting peer address")?;

            stream.set_nodelay(true)?;

            let tls_config = tls_config.clone();
            let services = self.services.clone();
            tokio::spawn(async move {
                let (session_handle, mut abort_rx) = MySqlSessionHandle::new();

                let server_handle = State::register_session(
                    &services.state,
                    &crate::common::PROTOCOL_NAME,
                    SessionStateInit {
                        remote_address: Some(remote_address),
                        handle: Box::new(session_handle),
                    },
                )
                .await
                .context("registering session")?;

                let wrapped_stream = server_handle.lock().await.wrap_stream(stream).await?;

                let session = MySqlSession::new(
                    server_handle,
                    services,
                    wrapped_stream,
                    tls_config,
                    remote_address,
                )
                .await;
                let span = session.make_logging_span();
                tokio::select! {
                    result = session.run().instrument(span) => match result {
                        Ok(_) => info!("Session ended"),
                        Err(e) => error!(error=%e, "Session failed"),
                    },
                    _ = abort_rx.recv() => {
                        warn!("Session aborted by admin");
                    },
                }

                Ok::<(), anyhow::Error>(())
            });
        }
    }

    async fn test_target(&self, target: Target) -> Result<(), TargetTestError> {
        let TargetOptions::MySql(options) = target.options else {
            return Err(TargetTestError::Misconfigured(
                "Not a MySQL target".to_owned(),
            ));
        };
        MySqlClient::connect(&options, ConnectionOptions::default())
            .await
            .map_err(|e| TargetTestError::ConnectionError(format!("{e}")))?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "MySQL"
    }
}

impl Debug for MySQLProtocolServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MySQLProtocolServer")
    }
}
