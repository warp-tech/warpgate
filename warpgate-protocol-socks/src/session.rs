use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::{info, info_span, warn};
use url::Url;
use warpgate_common::auth::{AuthSelector, redacted_selector};
use warpgate_common::{Protocol, Secret, TargetTcpOptions, UserSessionId, WarpgateError};
use warpgate_core::logging::TcpTunnelSubject;
use warpgate_core::{
    AuthOkPermit, DbAuthTransport, Services, WarpgateServerHandle, run_db_authorization,
};

use crate::error::SocksError;
use crate::proto::{self, Reply, RequestOutcome};
use crate::tunnel::{self, Counters, CountingStream, TunnelAudit};

/// How long a client gets to send its greeting and credentials, and again to
/// send its request. The wait for an administrator's approval is not counted.
pub const CLIENT_DEADLINE: Duration = Duration::from_secs(10);

pub struct SocksSession<S: AsyncRead + AsyncWrite + Send + Unpin> {
    stream: S,
    server_handle: Arc<Mutex<WarpgateServerHandle>>,
    id: UserSessionId,
    services: Services,
    remote_address: SocketAddr,
    /// Held between reading the credentials and the authorization flow asking
    /// for it.
    password: Option<Secret<String>>,
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin> DbAuthTransport for SocksSession<S> {
    type Error = SocksError;

    const PROTOCOL: Protocol = crate::common::PROTOCOL_NAME;
    const SUPPORTS_WEB_APPROVAL: bool = false;

    /// RFC 1929 sends the password together with the username, so there is
    /// nothing to ask for: the one that arrived is handed over once.
    async fn prompt_password(&mut self) -> Result<Option<Secret<String>>, SocksError> {
        Ok(self.password.take())
    }

    async fn send_auth_ok(&mut self, _permit: AuthOkPermit) -> Result<(), SocksError> {
        proto::write_auth_status(&mut self.stream, true).await
    }

    async fn external_url(&mut self) -> Result<Url, SocksError> {
        // Only used to show a web-approval link, which this protocol cannot
        Err(WarpgateError::InconsistentState("SOCKS has no web approval prompt".into()).into())
    }

    async fn send_web_approval_prompt(
        &mut self,
        _url: &Url,
        _identification_string: &str,
    ) -> Result<bool, SocksError> {
        Ok(false)
    }

    async fn send_denied(&mut self) -> Result<(), SocksError> {
        proto::write_auth_status(&mut self.stream, false).await?;
        let _ = self.stream.shutdown().await;
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin> SocksSession<S> {
    pub async fn new(
        server_handle: Arc<Mutex<WarpgateServerHandle>>,
        services: Services,
        stream: S,
        remote_address: SocketAddr,
    ) -> Self {
        let id = server_handle.lock().await.user_session_id();

        Self {
            stream,
            server_handle,
            id,
            services,
            remote_address,
            password: None,
        }
    }

    pub fn make_logging_span(&self) -> tracing::Span {
        let client_ip = self.remote_address.ip().to_string();
        info_span!("SOCKS", session=%self.id, %client_ip)
    }

    /// Answers a request with a failure and closes the connection, so that
    /// anything the client sent after it can't turn the close into a reset.
    async fn refuse(&mut self, reply: Reply) -> Result<(), SocksError> {
        proto::write_reply(&mut self.stream, reply, None).await?;
        let _ = self.stream.shutdown().await;
        Ok(())
    }

    pub async fn run(mut self) -> Result<(), SocksError> {
        let credentials = match tokio::time::timeout(CLIENT_DEADLINE, async {
            proto::negotiate_method(&mut self.stream).await?;
            proto::read_credentials(&mut self.stream).await
        })
        .await
        .map_err(|_| SocksError::ClientTimeout)?
        {
            Ok(credentials) => credentials,
            Err(SocksError::NoAcceptableMethod) => {
                warn!("Client does not offer username/password authentication");
                return Ok(());
            }
            Err(SocksError::Malformed(reason)) => {
                warn!(reason, "Malformed credentials");
                return self.send_denied().await;
            }
            Err(error) => return Err(error),
        };

        let username = credentials.username;
        self.password = Some(credentials.password);
        info!(username = %redacted_selector(&username), "Authenticating");

        let selector = AuthSelector::from(&username);
        let remote_ip = self.remote_address.ip();
        let session_id = self.id;
        let services = self.services.clone();
        let approved =
            match run_db_authorization(&mut self, &services, session_id, selector, remote_ip).await
            {
                Ok(Some(approved)) => approved,
                Ok(None) => return Ok(()),
                // Core raises every WarpgateError before the success byte, so a
                // denial here must look like any other refusal on the wire.
                Err(SocksError::Warpgate(error)) => {
                    warn!(%error, "Authentication failed");
                    return self.send_denied().await;
                }
                Err(error) => return Err(error),
            };

        let outcome = tokio::time::timeout(CLIENT_DEADLINE, proto::read_request(&mut self.stream))
            .await
            .map_err(|_| SocksError::ClientTimeout)??;
        let request = match outcome {
            RequestOutcome::Connect(request) => request,
            RequestOutcome::Reject(reply) => {
                warn!(?reply, "Unsupported request");
                return self.refuse(reply).await;
            }
        };

        let Ok(approved) = approved.narrow::<TargetTcpOptions>() else {
            warn!("Selected target is not a TCP target");
            return self.refuse(Reply::NotAllowed).await;
        };

        // The target is the one the user was authorized for. The request can
        // only agree with it, never pick another address.
        if !request.matches(&approved.options().host, approved.options().port) {
            warn!(requested = ?request, "Requested address is not the target's");
            return self.refuse(Reply::NotAllowed).await;
        }

        let admitted = self
            .server_handle
            .lock()
            .await
            .register_approved_target_session(approved)
            .await?;
        let options = admitted.options().clone();

        let mut upstream = match tunnel::connect(&options.host, options.port).await {
            Ok(upstream) => upstream,
            Err(error) => {
                warn!(%error, "Failed to connect to the target");
                return self.refuse(Reply::for_connect_error(error.kind())).await;
            }
        };

        let counters = Counters::new();
        let user_info = admitted.user_info();
        let mut audit = TunnelAudit::open(
            TcpTunnelSubject {
                session_id: self.id.0,
                user_id: user_info.id,
                username: user_info.username.clone(),
                target_id: admitted.target().id,
                target_name: admitted.target().name.clone(),
                client_ip: remote_ip.to_string(),
            },
            counters.clone(),
        );

        if let Err(error) = proto::write_reply(
            &mut self.stream,
            Reply::Succeeded,
            upstream.local_addr().ok(),
        )
        .await
        {
            audit.finish("error");
            return Err(error);
        }

        let idle_timeout = self.services.config.lock().await.store.socks.idle_timeout;
        let mut client = CountingStream::new(self.stream, counters.clone());
        let end = tunnel::pump(&mut client, &mut upstream, idle_timeout, &counters).await;
        audit.finish(end.reason());
        match end {
            tunnel::TunnelEnd::Closed => info!("Tunnel closed"),
            tunnel::TunnelEnd::IdleTimeout => info!("Tunnel closed after being idle"),
            tunnel::TunnelEnd::Error(error) => info!(%error, "Tunnel ended with an error"),
        }
        Ok(())
    }
}
