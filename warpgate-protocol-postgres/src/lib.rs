mod client;
mod common;
mod error;
mod session;
mod stream;

use std::fmt::Debug;
use std::sync::Arc;

use anyhow::{Context, Result};
use futures::FutureExt;
use futures::future::BoxFuture;
use rustls::ServerConfig;
use rustls::server::NoClientAuth;
use session::PostgresSession;
use tracing::{Instrument, error, info, warn};
use warpgate_common::ListenEndpoint;
use warpgate_common::helpers::net::{accept_loop, enable_tcp_keepalive};
use warpgate_core::{AbortSessionHandle, ProtocolServer, Services, State, UserSessionStateInit};
use warpgate_tls::{ResolveServerCert, TlsCertificateAndPrivateKey};

pub struct PostgresProtocolServer {
    services: Services,
}

impl PostgresProtocolServer {
    pub fn new(services: &Services) -> Self {
        Self {
            services: services.clone(),
        }
    }
}

impl ProtocolServer for PostgresProtocolServer {
    async fn bind(
        self,
        address: ListenEndpoint,
        proxy_protocol: bool,
        tls: Vec<TlsCertificateAndPrivateKey>,
    ) -> Result<BoxFuture<'static, Result<()>>> {
        let certificate_and_key = tls
            .into_iter()
            .next()
            .context("PostgreSQL requires a TLS certificate and key")?;

        let tls_config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(Arc::new(NoClientAuth))
        .with_cert_resolver(Arc::new(ResolveServerCert(Arc::new(
            certificate_and_key.into(),
        ))));

        let listener = address
            .tcp_accept_stream()
            .await
            .context("accepting connection")?;
        let services = self.services;
        Ok(async move {
            accept_loop(
                "PostgreSQL connection",
                listener,
                proxy_protocol,
                move |stream, remote_address| {
                    let tls_config = tls_config.clone();
                    let services = services.clone();
                    async move {
                        if let Err(error) = enable_tcp_keepalive(&stream) {
                            warn!(%error, "Failed to enable TCP keepalive");
                        }

                        let (session_handle, mut abort_rx) = AbortSessionHandle::new();

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
                            .await?;

                        let session = PostgresSession::new(
                            server_handle,
                            services,
                            wrapped_stream,
                            tls_config,
                            remote_address,
                        )
                        .await;

                        let span = session.make_logging_span();
                        // The outcome logs run in the span too: anything logged outside it
                        // is not attributed to the session. They are synchronous, so they
                        // enter the span directly rather than nesting another future in it.
                        tokio::select! {
                            result = session.run().instrument(span.clone()) => span.in_scope(|| match result {
                                Ok(()) => info!("Session ended"),
                                Err(e) => error!(error=%e, "Session failed"),
                            }),
                            _ = abort_rx.recv() => span.in_scope(|| {
                                warn!("Session aborted by admin");
                            }),
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
        "PostgreSQL"
    }
}

impl Debug for PostgresProtocolServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresProtocolServer").finish()
    }
}
