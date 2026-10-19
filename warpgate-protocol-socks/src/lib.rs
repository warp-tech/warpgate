mod common;
mod error;
mod proto;
mod session;
mod session_handle;
mod tunnel;

use std::fmt::Debug;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures::FutureExt;
use futures::future::BoxFuture;
use session::SocksSession;
use session_handle::SocksSessionHandle;
use socket2::{Socket, TcpKeepalive};
use tracing::{Instrument, error, info, warn};
use warpgate_common::ListenEndpoint;
use warpgate_common::helpers::net::accept_loop;
use warpgate_core::{ProtocolServer, Services, State, UserSessionStateInit};
use warpgate_tls::TlsCertificateAndPrivateKey;

pub struct SocksProtocolServer {
    services: Services,
}

impl SocksProtocolServer {
    pub fn new(services: &Services) -> Self {
        Self {
            services: services.clone(),
        }
    }
}

impl ProtocolServer for SocksProtocolServer {
    async fn bind(
        self,
        address: ListenEndpoint,
        proxy_protocol: bool,
        _tls: Vec<TlsCertificateAndPrivateKey>,
    ) -> Result<BoxFuture<'static, Result<()>>> {
        // SOCKS5 has no transport encryption: the RFC 1929 password and any
        // ticket cross the network as plain text.
        if !address.address().ip().is_loopback() {
            if !self
                .services
                .config
                .lock()
                .await
                .store
                .socks
                .allow_cleartext
            {
                bail!(
                    "SOCKS5 sends credentials unencrypted, so it only listens on a loopback address; \
                     `socks.listen` is {}. Set `socks.allow_cleartext: true` to listen there anyway",
                    address.address()
                );
            }
            warn!(
                address = %address.address(),
                "SOCKS5 is listening beyond loopback and credentials are sent unencrypted"
            );
        }

        let listener = address
            .tcp_accept_stream()
            .await
            .context("accepting connection")?;
        let services = self.services;
        Ok(async move {
            accept_loop(
                "SOCKS connection",
                listener,
                proxy_protocol,
                move |stream, remote_address| {
                    let services = services.clone();
                    async move {
                        // Keep tunnels that sit idle from being dropped by middleboxes
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
                                return Ok(());
                            }
                        };

                        let (session_handle, mut abort_rx) = SocksSessionHandle::new();

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

                        let session = SocksSession::new(
                            server_handle,
                            services,
                            wrapped_stream,
                            remote_address,
                        )
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
        "SOCKS"
    }
}

impl Debug for SocksProtocolServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocksProtocolServer").finish()
    }
}
