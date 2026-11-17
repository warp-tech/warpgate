//! Server-side UDP multitransport bootstrapping.
//!
//! [MS-RDPBCGR] 2.2.15.1/2.2.15.2 (`ironrdp_acceptor::Acceptor`) sends the
//! Initiate Multitransport Request and reports it via
//! [`ironrdp_acceptor::accept_finalize_with_multitransport`]. This module
//! establishes the sideband RDPEUDP2 + TLS + RDPEMT transport that request
//! bootstraps, for [`crate::server`] to migrate DVC channels onto via
//! [`ironrdp_dvc::DrdynvcServer::request_reliable_udp`].
//!
//! [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b8e7c588-51cb-455b-bb73-92d480903133

use core::net::{SocketAddr, SocketAddrV6};
use core::time::Duration;
use std::sync::Arc;

use ironrdp_pdu::rdp::multitransport::MultitransportRequestPdu;
use ironrdp_rdpemt::TunnelConfig;
use ironrdp_rdpeudp::ConnectionConfig;
use ironrdp_rdpeudp_tokio::{TunnelMessage, UdpAcceptConfig, UdpTransport, UdpTransportSender, accept_udp};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio_rustls::rustls;
use tracing::{debug, warn};

/// How long the full UDP accept sequence (initial datagram, RDPEUDP2
/// handshake, TLS, RDPEMT tunnel creation) may take before giving up and
/// continuing TCP-only.
const UDP_ACCEPT_TIMEOUT: Duration = Duration::from_secs(15);

/// Shared handle to an established sideband UDP transport.
///
/// `send()` uses `UdpTransportSender`, cloned once at construction from the
/// underlying `UdpTransport`. That handle is entirely independent of the
/// `Mutex` below, so it never contends with (or blocks behind) `recv()`,
/// which holds that lock for the full duration of its idle wait for the
/// next datagram: Sending and receiving already run over separate channels
/// fed by separate background tasks, so the two were never meant to share
/// one lock. `recv()` is intended for a single dedicated caller (the
/// `client_loop` select arm).
#[derive(Clone)]
pub(crate) struct UdpTransportHandle {
    sender: UdpTransportSender,
    transport: Arc<Mutex<UdpTransport>>,
}

impl UdpTransportHandle {
    fn new(transport: UdpTransport) -> Self {
        let sender = transport.sender();
        Self {
            sender,
            transport: Arc::new(Mutex::new(transport)),
        }
    }

    /// Sends one higher-layer (raw DVC) payload over the tunnel.
    ///
    /// A failure is logged here rather than propagated: The RDP session never
    /// fails over an optional sideband transport.
    pub(crate) async fn send(&self, data: Vec<u8>) {
        self.send_message(TunnelMessage::from(data)).await;
    }

    /// Sends one Tunnel Data PDU's content, sub-headers included; failures
    /// are handled as in [`Self::send`].
    pub(crate) async fn send_message(&self, message: TunnelMessage) {
        if let Err(error) = self.sender.send_message(message).await {
            warn!(%error, "Failed to send data over UDP transport");
        }
    }

    pub(crate) async fn recv(&self) -> Option<TunnelMessage> {
        self.transport.lock().await.recv_message().await
    }
}

/// The address to bind the sideband UDP socket to: `bind` itself, unless its
/// IP is unspecified and the local address the client reached over TCP is
/// known, in which case that address (at `bind`'s port). Replies must leave
/// from the address the client sent to, which a socket bound to the
/// unspecified address does not guarantee on a host with several addresses.
///
/// A link-local IPv6 address keeps its scope ID, without which it cannot be
/// bound.
pub(crate) fn sideband_bind_addr(bind: SocketAddr, connection_local: Option<SocketAddr>) -> SocketAddr {
    let Some(local) = connection_local.filter(|_| bind.ip().is_unspecified()) else {
        return bind;
    };
    match local {
        SocketAddr::V6(v6) if v6.ip().to_ipv4_mapped().is_none() => {
            SocketAddr::V6(SocketAddrV6::new(*v6.ip(), bind.port(), 0, v6.scope_id()))
        }
        _ => SocketAddr::new(local.ip().to_canonical(), bind.port()),
    }
}

/// Attempts to establish the sideband UDP transport for one Initiate
/// Multitransport Request.
///
/// Binds a fresh socket to `udp_bind_addr` for this attempt, avoiding any
/// shared, long-lived UDP socket state to manage. This assumes at most one
/// live attempt at a time; under
/// [`RdpServerOptions::preempt_existing_session`](crate::server::RdpServerOptions::preempt_existing_session)
/// a candidate session's negotiation can overlap the still-live session it
/// is preempting, and `udp_bind_addr` is typically the same host and port for
/// both (see [`RdpServerBuilder::with_udp_transport`](crate::RdpServerBuilder::with_udp_transport)),
/// so the second bind fails with `AddrInUse`. That failure is handled below
/// like any other: The overlapping connection degrades to TCP-only rather
/// than failing.
///
/// Any failure (bind, RDPEUDP2 handshake, TLS, RDPEMT tunnel) is logged and
/// reported as `None` rather than propagated: An optional sideband transport
/// failing to come up is never a reason to fail the RDP connection, matching
/// the reference client implementation's posture.
pub(crate) async fn accept(
    udp_bind_addr: SocketAddr,
    tls_config: Arc<rustls::ServerConfig>,
    request: &MultitransportRequestPdu,
) -> Option<UdpTransportHandle> {
    let socket = match UdpSocket::bind(udp_bind_addr).await {
        Ok(socket) => socket,
        Err(error) => {
            warn!(%error, %udp_bind_addr, "Failed to bind UDP socket for multitransport, continuing TCP-only");
            return None;
        }
    };

    let config = UdpAcceptConfig {
        tls_config,
        tunnel_config: TunnelConfig {
            request_id: request.request_id,
            security_cookie: request.security_cookie,
        },
        connection_config: ConnectionConfig::default(),
        accept_timeout: UDP_ACCEPT_TIMEOUT,
    };

    match accept_udp(socket, config).await {
        Ok(transport) => {
            debug!("Sideband UDP transport established");
            Some(UdpTransportHandle::new(transport))
        }
        Err(error) => {
            warn!(%error, "Failed to establish sideband UDP transport, continuing TCP-only");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    const V6_LOCAL: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xc518);

    #[test]
    fn unspecified_bind_takes_the_connection_address() {
        let bind = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 3389);
        let local = SocketAddr::new(IpAddr::V6(V6_LOCAL), 3389);
        assert_eq!(
            sideband_bind_addr(bind, Some(local)),
            SocketAddr::new(IpAddr::V6(V6_LOCAL), 3389)
        );
    }

    #[test]
    fn ipv4_client_on_a_dual_stack_listener_binds_ipv4() {
        let bind = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 3389);
        let mapped = SocketAddr::new(IpAddr::V6(Ipv4Addr::new(192, 0, 2, 7).to_ipv6_mapped()), 3389);
        assert_eq!(
            sideband_bind_addr(bind, Some(mapped)),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 3389)
        );
    }

    #[test]
    fn a_link_local_address_keeps_its_scope() {
        let bind = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 3389);
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let local = SocketAddr::V6(SocketAddrV6::new(link_local, 50000, 0, 2));
        assert_eq!(
            sideband_bind_addr(bind, Some(local)),
            SocketAddr::V6(SocketAddrV6::new(link_local, 3389, 0, 2))
        );
    }

    #[test]
    fn an_explicit_bind_address_is_kept() {
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 3390);
        let local = SocketAddr::new(IpAddr::V6(V6_LOCAL), 3389);
        assert_eq!(sideband_bind_addr(bind, Some(local)), bind);
    }

    #[test]
    fn unknown_connection_address_keeps_the_bind() {
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 3389);
        assert_eq!(sideband_bind_addr(bind, None), bind);
    }
}
