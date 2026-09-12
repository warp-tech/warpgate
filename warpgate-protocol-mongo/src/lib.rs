mod client;
mod common;
mod error;
mod session;
mod session_handle;
mod stream;
use std::fmt::Debug;
use std::sync::Arc;

use anyhow::{Context, Result};
use futures::FutureExt;
use futures::future::BoxFuture;
use rustls::ServerConfig;
use rustls::server::NoClientAuth;
use tokio_rustls::TlsAcceptor;
use tracing::{Instrument, error, info, warn};
use warpgate_common::ListenEndpoint;
use warpgate_common::helpers::net::accept_loop;
use warpgate_core::{ProtocolServer, Services, State, UserSessionStateInit};
use warpgate_tls::{ResolveServerCert, TlsCertificateAndPrivateKey};

use crate::session::MongoSession;
use crate::session_handle::MongoSessionHandle;

pub struct MongoProtocolServer {
    services: Services,
}

impl MongoProtocolServer {
    pub fn new(services: &Services) -> Self {
        Self {
            services: services.clone(),
        }
    }
}

impl ProtocolServer for MongoProtocolServer {
    async fn bind(
        self,
        address: ListenEndpoint,
        proxy_protocol: bool,
        tls: Vec<TlsCertificateAndPrivateKey>,
    ) -> Result<BoxFuture<'static, Result<()>>> {
        let certificate_and_key = tls
            .into_iter()
            .next()
            .context("MongoDB requires a TLS certificate and key")?;

        let tls_config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(Arc::new(NoClientAuth))
        .with_cert_resolver(Arc::new(ResolveServerCert(Arc::new(
            certificate_and_key.into(),
        ))));

        let listener = address.tcp_accept_stream().await?;
        // MongoDB clients speak TLS from the first byte (there is no
        // STARTTLS-style upgrade), so the handshake happens before the
        // session is registered.
        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

        let services = self.services;
        Ok(async move {
            accept_loop(
                "MongoDB connection",
                listener,
                proxy_protocol,
                move |stream, remote_address| {
                    let tls_acceptor = tls_acceptor.clone();
                    let services = services.clone();
                    async move {
                        let stream = tls_acceptor
                            .accept(stream)
                            .await
                            .context("TLS handshake failed")?;

                        let (session_handle, mut abort_rx) = MongoSessionHandle::new();

                        let (server_handle, wrapped_stream) =
                            State::register_user_session_with_stream(
                                &services.state,
                                crate::common::PROTOCOL_NAME,
                                UserSessionStateInit {
                                    remote_address: Some(remote_address),
                                    handle: Box::new(session_handle),
                                },
                                stream,
                            )
                            .await
                            .context("registering session")?;

                        let session =
                            MongoSession::new(server_handle, services, wrapped_stream, remote_address)
                                .await;
                        let span = session.make_logging_span();
                        tokio::select! {
                            result = session.run().instrument(span) => match result {
                                Ok(()) => info!("Session ended"),
                                Err(e) => error!(error=%e, "Session failed"),
                            },
                            _ = abort_rx.recv() => {
                                warn!("Session aborted by admin");
                            },
                        }

                        Ok(())
                    }
                },
            )
            .await;
            Ok(())
        }
        .boxed())
    }

    fn name(&self) -> &'static str {
        "MongoDB"
    }
}

impl Debug for MongoProtocolServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MongoProtocolServer").finish()
    }
}
