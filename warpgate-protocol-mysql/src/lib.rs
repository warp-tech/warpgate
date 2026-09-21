mod client;
mod common;
mod error;
mod relay;
mod session;
mod stream;
use std::fmt::Debug;

use anyhow::{Context, Result};
use futures::FutureExt;
use futures::future::BoxFuture;
use tracing::{Instrument, error, info, warn};
use warpgate_common::ListenEndpoint;
use warpgate_common::helpers::net::{accept_loop, enable_tcp_keepalive};
use warpgate_core::{AbortSessionHandle, ProtocolServer, Services, State, UserSessionStateInit};
use warpgate_tls::{TlsCertificateAndPrivateKey, configure_tls_acceptor};

use crate::session::MySqlSession;

pub struct MySQLProtocolServer {
    services: Services,
}

impl MySQLProtocolServer {
    pub fn new(services: &Services) -> Self {
        Self {
            services: services.clone(),
        }
    }
}

impl ProtocolServer for MySQLProtocolServer {
    async fn bind(
        self,
        address: ListenEndpoint,
        proxy_protocol: bool,
        tls: Vec<TlsCertificateAndPrivateKey>,
    ) -> Result<BoxFuture<'static, Result<()>>> {
        let certificate_and_key = tls
            .into_iter()
            .next()
            .context("MySQL requires a TLS certificate and key")?;

        let tls_config = configure_tls_acceptor(certificate_and_key)?;

        let listener = address.tcp_accept_stream().await?;

        let services = self.services;
        Ok(async move {
            accept_loop(
                "MySQL connection",
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
                            .await
                            .context("registering session")?;

                        let session = MySqlSession::new(
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
        "MySQL"
    }
}

impl Debug for MySQLProtocolServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MySQLProtocolServer").finish()
    }
}
