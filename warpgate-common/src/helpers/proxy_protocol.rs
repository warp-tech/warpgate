use std::io::Result as IoResult;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, bail};
use poem::listener::Acceptor;
use poem::web::{LocalAddr, RemoteAddr};
use ppp::{HeaderResult, PartialResult};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::helpers::concurrent_acceptor::{Accepted, ConcurrentAcceptor};

const V2_MINIMUM_HEADER_LENGTH: usize = 16;
const V1_MAX_HEADER_LENGTH: usize = 108;
const MAX_PROXY_PROTOCOL_HEADER_LENGTH: usize = V2_MINIMUM_HEADER_LENGTH + u16::MAX as usize;

/// A conforming peer sends the whole header up front, so the budget only has to
/// outlast network latency.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn remote_address(
    stream: &mut TcpStream,
    proxy_protocol: bool,
) -> anyhow::Result<SocketAddr> {
    let peer_address = stream.peer_addr().context("getting peer address")?;
    if !proxy_protocol {
        return Ok(peer_address);
    }

    Ok(read_header(stream).await?.unwrap_or(peer_address))
}

pub enum MaybeProxyProtocolAcceptor<A: Acceptor> {
    Direct(A),
    Reading(ConcurrentAcceptor<A::Io>),
}

impl<A: Acceptor + 'static> MaybeProxyProtocolAcceptor<A> {
    pub fn new(inner: A, proxy_protocol: bool) -> Self {
        if !proxy_protocol {
            return Self::Direct(inner);
        }
        Self::Reading(ConcurrentAcceptor::new(
            inner,
            |(mut io, local_addr, remote_addr, scheme): Accepted<A::Io>| async move {
                let remote_addr = match read_header(&mut io).await? {
                    Some(address) => RemoteAddr(address.into()),
                    None => remote_addr,
                };
                Ok((io, local_addr, remote_addr, scheme))
            },
        ))
    }
}

impl<A: Acceptor + 'static> Acceptor for MaybeProxyProtocolAcceptor<A> {
    type Io = A::Io;

    fn local_addr(&self) -> Vec<LocalAddr> {
        match self {
            Self::Direct(inner) => inner.local_addr(),
            Self::Reading(inner) => inner.local_addr(),
        }
    }

    async fn accept(&mut self) -> IoResult<Accepted<Self::Io>> {
        match self {
            Self::Direct(inner) => inner.accept().await,
            Self::Reading(inner) => inner.accept().await,
        }
    }
}

async fn read_header<R: AsyncRead + Unpin>(stream: &mut R) -> anyhow::Result<Option<SocketAddr>> {
    timeout(READ_TIMEOUT, read_header_inner(stream))
        .await
        .context("timed out reading PROXY protocol header")?
}

async fn read_header_inner<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> anyhow::Result<Option<SocketAddr>> {
    let mut bytes = Vec::with_capacity(V2_MINIMUM_HEADER_LENGTH);

    loop {
        if bytes.len() >= MAX_PROXY_PROTOCOL_HEADER_LENGTH {
            bail!("PROXY protocol header is too long");
        }

        let mut byte = [0u8; 1];
        stream
            .read_exact(&mut byte)
            .await
            .context("reading PROXY protocol header")?;
        bytes.push(byte[0]);

        if bytes.len() == V2_MINIMUM_HEADER_LENGTH && bytes.starts_with(ppp::v2::PROTOCOL_PREFIX) {
            // The v2 payload length is the last two bytes of the fixed 16-byte header.
            let length_bytes: [u8; 2] = bytes
                .get(V2_MINIMUM_HEADER_LENGTH - 2..)
                .and_then(|s| s.try_into().ok())
                .context("PROXY protocol v2 header missing length field")?;
            let payload_length = u16::from_be_bytes(length_bytes) as usize;
            let header_length = V2_MINIMUM_HEADER_LENGTH + payload_length;
            let remaining_length = header_length - bytes.len();
            bytes.resize(header_length, 0);
            let payload = bytes
                .get_mut(V2_MINIMUM_HEADER_LENGTH..)
                .context("PROXY protocol v2 payload buffer too short")?;
            stream
                .read_exact(payload)
                .await
                .context("reading PROXY protocol v2 payload")?;
            debug_assert_eq!(remaining_length, payload_length);
        }

        if bytes.starts_with(b"PROXY ") && !bytes.ends_with(b"\r\n") {
            if bytes.len() > V1_MAX_HEADER_LENGTH {
                bail!("PROXY protocol v1 header is too long");
            }
            continue;
        }

        let header = HeaderResult::parse(&bytes);
        if header.is_complete() {
            return source_address(header);
        }
    }
}

fn source_address(header: HeaderResult<'_>) -> anyhow::Result<Option<SocketAddr>> {
    match header {
        HeaderResult::V1(Ok(header)) => source_address_v1(header.addresses),
        HeaderResult::V2(Ok(header)) => source_address_v2(&header),
        HeaderResult::V1(Err(error)) => Err(error).context("invalid PROXY protocol v1 header"),
        HeaderResult::V2(Err(error)) => Err(error).context("invalid PROXY protocol v2 header"),
    }
}

#[allow(clippy::unnecessary_wraps)]
fn source_address_v1(addresses: ppp::v1::Addresses) -> anyhow::Result<Option<SocketAddr>> {
    match addresses {
        ppp::v1::Addresses::Unknown => Ok(None),
        ppp::v1::Addresses::Tcp4(addresses) => Ok(Some(SocketAddr::new(
            addresses.source_address.into(),
            addresses.source_port,
        ))),
        ppp::v1::Addresses::Tcp6(addresses) => Ok(Some(SocketAddr::new(
            addresses.source_address.into(),
            addresses.source_port,
        ))),
    }
}

fn source_address_v2(header: &ppp::v2::Header<'_>) -> anyhow::Result<Option<SocketAddr>> {
    if header.command == ppp::v2::Command::Local {
        return Ok(None);
    }

    if header.protocol == ppp::v2::Protocol::Unspecified {
        return Ok(None);
    }
    if header.protocol != ppp::v2::Protocol::Stream {
        bail!("PROXY protocol v2 header does not describe a TCP stream");
    }

    match header.addresses {
        ppp::v2::Addresses::Unspecified | ppp::v2::Addresses::Unix(_) => Ok(None),
        ppp::v2::Addresses::IPv4(addresses) => Ok(Some(SocketAddr::new(
            addresses.source_address.into(),
            addresses.source_port,
        ))),
        ppp::v2::Addresses::IPv6(addresses) => Ok(Some(SocketAddr::new(
            addresses.source_address.into(),
            addresses.source_port,
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use poem::listener::{Listener, TcpListener};
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    use super::*;

    #[tokio::test]
    async fn stalled_header_does_not_block_later_connections() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .into_acceptor()
            .await
            .unwrap();
        let address = listener
            .local_addr()
            .into_iter()
            .find_map(|address| address.0.as_socket_addr().copied())
            .unwrap();

        // Queued before the acceptor starts polling, so it is accepted first.
        let _stalled = TcpStream::connect(address).await.unwrap();
        let mut acceptor = MaybeProxyProtocolAcceptor::new(listener, true);

        let mut second = TcpStream::connect(address).await.unwrap();
        second
            .write_all(b"PROXY TCP4 203.0.113.10 10.0.0.2 42300 443\r\n")
            .await
            .unwrap();

        let (_io, _, remote_addr, _) = timeout(Duration::from_secs(5), acceptor.accept())
            .await
            .expect("a peer that sent no header blocked the next connection")
            .unwrap();
        assert_eq!(
            remote_addr.as_socket_addr(),
            Some(&"203.0.113.10:42300".parse().unwrap())
        );
    }

    async fn read_header_from(bytes: &[u8]) -> anyhow::Result<Option<SocketAddr>> {
        let mut input = bytes;
        read_header(&mut input).await
    }

    fn v2_header(version_command: u8, family_protocol: u8, payload: &[u8]) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(ppp::v2::PROTOCOL_PREFIX);
        header.push(version_command);
        header.push(family_protocol);
        header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        header.extend_from_slice(payload);
        header
    }

    #[tokio::test]
    async fn parses_v1_tcp4_header() {
        let address = read_header_from(b"PROXY TCP4 203.0.113.10 10.0.0.2 42300 443\r\n")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(address, "203.0.113.10:42300".parse().unwrap());
    }

    #[tokio::test]
    async fn parses_v1_tcp6_header() {
        let address = read_header_from(b"PROXY TCP6 2001:db8::1 2001:db8::2 42300 443\r\n")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(address, "[2001:db8::1]:42300".parse().unwrap());
    }

    #[tokio::test]
    async fn parses_v1_unknown_header() {
        let address = read_header_from(b"PROXY UNKNOWN\r\n").await.unwrap();
        assert_eq!(address, None);
    }

    #[tokio::test]
    async fn parses_v2_tcp4_address() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&Ipv4Addr::new(203, 0, 113, 10).octets());
        payload.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 2).octets());
        payload.extend_from_slice(&42300u16.to_be_bytes());
        payload.extend_from_slice(&443u16.to_be_bytes());

        let address = read_header_from(&v2_header(0x21, 0x11, &payload))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(address, "203.0.113.10:42300".parse().unwrap());
    }

    #[tokio::test]
    async fn parses_v2_tcp6_address() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        payload.extend_from_slice(&Ipv6Addr::UNSPECIFIED.octets());
        payload.extend_from_slice(&12345u16.to_be_bytes());
        payload.extend_from_slice(&443u16.to_be_bytes());

        let address = read_header_from(&v2_header(0x21, 0x21, &payload))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(address, "[::1]:12345".parse().unwrap());
    }

    #[tokio::test]
    async fn parses_v2_local_as_fallback() {
        let address = read_header_from(&v2_header(0x20, 0x00, &[])).await.unwrap();
        assert_eq!(address, None);
    }

    #[tokio::test]
    async fn rejects_v2_datagram_header() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&Ipv4Addr::new(203, 0, 113, 10).octets());
        payload.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 2).octets());
        payload.extend_from_slice(&42300u16.to_be_bytes());
        payload.extend_from_slice(&443u16.to_be_bytes());

        let error = read_header_from(&v2_header(0x21, 0x12, &payload))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("does not describe a TCP stream"));
    }

    #[tokio::test]
    async fn rejects_invalid_header() {
        let error = read_header_from(b"NOPE").await.unwrap_err();
        assert!(error.to_string().contains("invalid PROXY protocol"));
    }

    #[tokio::test]
    async fn rejects_incomplete_header() {
        let error = read_header_from(b"PROXY TCP4 203.0.113.10")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("reading PROXY protocol header"));
    }

    #[tokio::test]
    async fn rejects_oversized_header() {
        let mut header = Vec::from("PROXY UNKNOWN ");
        header.resize(MAX_PROXY_PROTOCOL_HEADER_LENGTH + 1, b'a');

        let error = read_header_from(&header).await.unwrap_err();
        assert!(error.to_string().contains("PROXY protocol"));
    }

    #[tokio::test]
    async fn leaves_bytes_after_v1_header_unread() {
        let mut input = b"PROXY UNKNOWN\r\nNEXT".as_slice();
        let address = read_header(&mut input).await.unwrap();
        assert_eq!(address, None);
        assert_eq!(input, b"NEXT");
    }

    #[tokio::test]
    async fn leaves_bytes_after_v2_header_unread() {
        let mut bytes = v2_header(0x20, 0x00, &[]);
        bytes.extend_from_slice(b"NEXT");
        let mut input = bytes.as_slice();

        let address = read_header(&mut input).await.unwrap();
        assert_eq!(address, None);
        assert_eq!(input, b"NEXT");
    }
}
