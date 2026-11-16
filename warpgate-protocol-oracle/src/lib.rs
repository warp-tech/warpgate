//! Warpgate protocol server for Oracle Database (TNS/TTC, O5LOGON).
//!
//! The transparent-proxy primitives live in the `warpgate-oracle-tns` crate; this crate
//! wires them into Warpgate (listener, per-connection session, user/target
//! authorization, SQL audit). Oracle is served dual-mode on one port — a plain
//! TCP TNS connection or TCPS (TLS from the first byte, no STARTTLS), selected by
//! peeking the first byte — so `bind()` still provisions a TLS certificate for
//! the TCPS path, and the session upgrades to TLS only when the client opened
//! with a TLS ClientHello.
//!
//! See `session.rs` for the login flow and its security model.

mod client;
mod common;
mod error;
mod session;
mod session_handle;
mod stream;
mod test_connection;

use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use futures::FutureExt;
use futures::future::BoxFuture;
use rustls::ServerConfig;
use rustls::server::NoClientAuth;
use session::OracleSession;
use session_handle::OracleSessionHandle;
use socket2::{Socket, TcpKeepalive};
pub use test_connection::test_connection;
use tokio::sync::Semaphore;
use tracing::{Instrument, error, info, warn};
use warpgate_common::ListenEndpoint;
use warpgate_common::helpers::net::accept_loop;
use warpgate_core::{ProtocolServer, Services, State, UserSessionStateInit};
use warpgate_tls::{ResolveServerCert, TlsCertificateAndPrivateKey};

/// How many Oracle logins may be in progress at once. Each one holds a
/// connection to the target database until the client has authenticated, so
/// the cap bounds what unauthenticated clients can make the gateway open.
const MAX_PENDING_LOGINS: usize = 64;

pub struct OracleProtocolServer {
    services: Services,
}

impl OracleProtocolServer {
    pub fn new(services: &Services) -> Self {
        Self {
            services: services.clone(),
        }
    }
}

impl ProtocolServer for OracleProtocolServer {
    async fn bind(
        self,
        address: ListenEndpoint,
        proxy_protocol: bool,
        tls: Vec<TlsCertificateAndPrivateKey>,
    ) -> Result<BoxFuture<'static, Result<()>>> {
        let certificate_and_key = tls
            .into_iter()
            .next()
            .context("Oracle TCPS requires a TLS certificate and key")?;

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
        let pending_logins = Arc::new(Semaphore::new(MAX_PENDING_LOGINS));
        Ok(async move {
            accept_loop(
                "Oracle connection",
                listener,
                proxy_protocol,
                move |stream, remote_address| {
                    let tls_config = tls_config.clone();
                    let services = services.clone();
                    let pending_logins = pending_logins.clone();
                    async move {
                        let Ok(login_permit) = pending_logins.try_acquire_owned() else {
                            warn!(%remote_address, "Too many Oracle logins in progress; refusing");
                            return Ok(());
                        };
                        // Enable TCP keepalive so an idle connection (e.g. during a
                        // long-running query) is not dropped by an intermediary.
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

                        let (session_handle, mut abort_rx) = OracleSessionHandle::new();

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

                        let session = OracleSession::new(
                            server_handle,
                            services,
                            wrapped_stream,
                            tls_config,
                            remote_address,
                            login_permit,
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
        "Oracle"
    }
}

impl Debug for OracleProtocolServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OracleProtocolServer").finish()
    }
}
