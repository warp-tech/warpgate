mod client;
mod common;
mod error;
mod session;
mod session_handle;

use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use futures::future::BoxFuture;
use futures::{FutureExt, StreamExt};
use rustls::ServerConfig;
use rustls::server::NoClientAuth;
use session::RedisSession;
use session_handle::RedisSessionHandle;
use socket2::{Socket, TcpKeepalive};
use tokio::net::TcpStream;
use tracing::{Instrument, error, info, warn};
use warpgate_common::ListenEndpoint;
use warpgate_common::helpers::net::accept_client;
use warpgate_core::{ProtocolServer, Services, State, UserSessionStateInit};
use warpgate_tls::{MaybeTlsStream, ResolveServerCert, ServerTlsStream, TlsCertificateAndPrivateKey};

pub struct RedisProtocolServer {
    services: Services,
}

impl RedisProtocolServer {
    pub fn new(services: &Services) -> Self {
        Self {
            services: services.clone(),
        }
    }
}

impl ProtocolServer for RedisProtocolServer {
    async fn bind(
        self,
        address: ListenEndpoint,
        proxy_protocol: bool,
        tls: Vec<TlsCertificateAndPrivateKey>,
    ) -> Result<BoxFuture<'static, Result<()>>> {
        // Unlike MySQL/Postgres, Redis has no in-protocol STARTTLS: a listener
        // either terminates TLS for every connection or is plaintext-only. No
        // certificate configured just means this listener runs in plaintext.
        let tls_config = tls
            .into_iter()
            .next()
            .map(|certificate_and_key| -> Result<_> {
                Ok(Arc::new(
                    ServerConfig::builder_with_provider(Arc::new(
                        rustls::crypto::aws_lc_rs::default_provider(),
                    ))
                    .with_safe_default_protocol_versions()?
                    .with_client_cert_verifier(Arc::new(NoClientAuth))
                    .with_cert_resolver(Arc::new(ResolveServerCert(Arc::new(
                        certificate_and_key.into(),
                    )))),
                ))
            })
            .transpose()?;

        let mut listener = address
            .tcp_accept_stream()
            .await
            .map_err(anyhow::Error::from)?;
        let services = self.services;
        Ok(async move {
            loop {
                let Some(mut stream) = listener.next().await else {
                    return Ok(());
                };

                let Some(remote_address) = accept_client(&mut stream, proxy_protocol).await else {
                    continue;
                };

                let stream = (|| {
                    let socket = Socket::from(stream.into_std()?);
                    let keepalive = TcpKeepalive::new()
                        .with_time(Duration::from_secs(60))
                        .with_interval(Duration::from_secs(10))
                        .with_retries(3);
                    socket.set_tcp_keepalive(&keepalive)?;
                    socket.set_tcp_nodelay(true)?;
                    tokio::net::TcpStream::from_std(socket.into())
                })();

                let stream = match stream {
                    Ok(stream) => stream,
                    Err(error) => {
                        warn!(%error, "Failed to set up an accepted connection");
                        continue;
                    }
                };

                let tls_config = tls_config.clone();
                let services = services.clone();
                tokio::spawn(async move {
                    let mut stream =
                        MaybeTlsStream::<TcpStream, ServerTlsStream<TcpStream>>::new(stream);
                    if let Some(tls_config) = tls_config {
                        stream = stream.upgrade(tls_config, Bytes::new()).await?;
                    }

                    let (session_handle, mut abort_rx) = RedisSessionHandle::new();

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

                    let session =
                        RedisSession::new(server_handle, services, wrapped_stream, remote_address)
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

                    Ok::<(), anyhow::Error>(())
                });
            }
        }
        .boxed())
    }

    fn name(&self) -> &'static str {
        "Redis"
    }
}

impl Debug for RedisProtocolServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisProtocolServer").finish()
    }
}
