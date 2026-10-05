use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use russh::ChannelStream;
use russh::client::{Handle, Msg};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{UnboundedReceiver, channel};
use tokio::task::JoinHandle;
use tracing::*;
use uuid::Uuid;
use warpgate_common::UserSessionId;
use warpgate_core::Services;
use warpgate_db_entities::Parameters;
use warpgate_db_entities::Parameters::SshHostKeyVerificationMode;

use super::handler::{ClientHandler, ClientHandlerEvent};
use super::{ConnectionError, Connector, RCEvent, resolve_ssh_chain};

/// A connection to a non-SSH target: direct TCP, or through an SSH jump host.
pub enum TargetStream {
    Tcp(TcpStream),
    Tunnel(Box<SshTunnel>),
}

/// Connect to `host:port` directly, or through the `jump_host` SSH target if one is set.
pub async fn connect_target_stream(
    services: &Services,
    session_id: UserSessionId,
    jump_host: Option<Uuid>,
    host: &str,
    port: u16,
    logged_in_username: Option<&String>,
) -> Result<TargetStream, ConnectionError> {
    if let Some(jump_host) = jump_host {
        let tunnel = open_ssh_tunnel(
            services,
            session_id,
            jump_host,
            host,
            port,
            logged_in_username,
        )
        .await?;
        return Ok(TargetStream::Tunnel(Box::new(tunnel)));
    }
    let stream = TcpStream::connect((host, port)).await?;
    stream.set_nodelay(true)?;
    Ok(TargetStream::Tcp(stream))
}

impl AsyncRead for TargetStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tunnel(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TargetStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tunnel(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tunnel(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tunnel(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// A TCP connection to `host:port` opened from the far end of an SSH jump
/// host chain, for protocols other than SSH (e.g. database targets).
///
/// Dropping it closes the channel and tears down the SSH session.
pub struct SshTunnel {
    stream: ChannelStream<Msg>,
    _session: Handle<ClientHandler>,
    _session_events: UnboundedReceiver<ClientHandlerEvent>,
    event_task: JoinHandle<()>,
}

/// Connect through the SSH chain ending at the `jump_host` target and open a
/// `direct-tcpip` channel from its last hop to `host:port`.
///
/// There is no interactive client to ask about unknown host keys, so in the
/// prompt mode they are rejected. Otherwise the jump host's key has to
/// be trusted beforehand, e.g. by connecting to it as an SSH target once.
pub async fn open_ssh_tunnel(
    services: &Services,
    session_id: UserSessionId,
    jump_host: Uuid,
    host: &str,
    port: u16,
    logged_in_username: Option<&String>,
) -> Result<SshTunnel, ConnectionError> {
    let chain = resolve_ssh_chain(services, jump_host, logged_in_username)
        .await?
        .into_iter()
        .map(|hop| hop.ssh_options)
        .collect();

    let (tx, mut rx) = channel(16);
    let event_task = tokio::spawn({
        let services = services.clone();
        async move {
            while let Some(event) = rx.recv().await {
                if let RCEvent::HostKeyUnknown(key, host, port, reply) = event {
                    // Mirrors `ServerSession::handle_unknown_host_key`, except that
                    // nobody can answer a prompt here, so it counts as a rejection.
                    // `Ignore` never gets here - the key is accepted without a lookup.
                    let accept = match Parameters::Entity::get(&services.db).await {
                        Ok(params) => {
                            params.ssh_host_key_verification
                                == SshHostKeyVerificationMode::AutoAccept
                        }
                        Err(error) => {
                            error!(?error, "Failed to read the host key verification mode");
                            false
                        }
                    };
                    if accept {
                        info!(%host, port, "Accepted untrusted jump host key (auto-accept is enabled)");
                    } else {
                        warn!(
                            %host,
                            port,
                            key_type = %key.algorithm(),
                            "Jump host key is not trusted. Connect to this host as an SSH target once to accept it."
                        );
                    }
                    let _ = reply.send(accept);
                }
            }
        }
        .instrument(Span::current())
    });

    let connector = Connector {
        id: session_id,
        tx,
        services: services.clone(),
    };

    let result = async {
        let super::Connection(session, session_events) = connector.connect_chain(chain).await?;
        info!(%host, port, "Opening direct-tcpip channel through jump host");
        let channel = session
            .channel_open_direct_tcpip(host.to_string(), u32::from(port), "127.0.0.1", 0)
            .await?;
        Ok::<_, ConnectionError>((channel.into_stream(), session, session_events))
    }
    .await;

    match result {
        Ok((stream, session, session_events)) => Ok(SshTunnel {
            stream,
            _session: session,
            _session_events: session_events,
            event_task,
        }),
        Err(error) => {
            event_task.abort();
            Err(error)
        }
    }
}

impl Drop for SshTunnel {
    fn drop(&mut self) {
        self.event_task.abort();
    }
}

impl AsyncRead for SshTunnel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for SshTunnel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
