use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, bail};
use bytes::Bytes;
use ppp::{HeaderResult, PartialResult};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use warpgate_tls::PrefixedStream;

/// Content type of a TLS handshake record. No PROXY header starts with it
const TLS_HANDSHAKE_RECORD_TYPE: u8 = 0x16;

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

/// The PROXY header found before a TLS handshake
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyHeader {
    /// The listener does not use the PROXY protocol
    NotExpected,
    /// `None` for a `LOCAL` or `UNKNOWN` header, which has no client address
    Present(Option<SocketAddr>),
    /// The listener uses the PROXY protocol, but the stream starts with a TLS
    /// handshake. This is not an error, because the client is only identified
    /// once TLS completes
    Missing,
}

/// Reads the PROXY header, if any. The returned stream starts at the TLS
/// handshake
pub async fn read_header_before_tls<Io: AsyncRead + Unpin>(
    mut io: Io,
    proxy_protocol: bool,
) -> anyhow::Result<(PrefixedStream<Io>, ProxyHeader)> {
    if !proxy_protocol {
        return Ok((
            PrefixedStream::new(io, Bytes::new()),
            ProxyHeader::NotExpected,
        ));
    }

    let (header, prefix) = timeout(READ_TIMEOUT, async {
        let mut first = [0u8; 1];
        io.read_exact(&mut first)
            .await
            .context("reading PROXY protocol header")?;
        if first == [TLS_HANDSHAKE_RECORD_TYPE] {
            return Ok((ProxyHeader::Missing, Bytes::copy_from_slice(&first)));
        }
        let address = read_header_inner(&mut first.as_slice().chain(&mut io)).await?;
        anyhow::Ok((ProxyHeader::Present(address), Bytes::new()))
    })
    .await
    .context("timed out reading PROXY protocol header")??;

    Ok((PrefixedStream::new(io, prefix), header))
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

    use super::*;

    async fn remainder<R: AsyncRead + Unpin>(mut stream: R) -> Vec<u8> {
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
        rest
    }

    #[tokio::test]
    async fn tls_without_header_is_reported_missing_and_left_intact() {
        let client_hello = [0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x02];
        let (stream, header) = read_header_before_tls(client_hello.as_slice(), true)
            .await
            .unwrap();
        assert_eq!(header, ProxyHeader::Missing);
        assert_eq!(remainder(stream).await, client_hello);
    }

    #[tokio::test]
    async fn header_before_tls_is_consumed() {
        let input = b"PROXY TCP4 203.0.113.10 10.0.0.2 42300 443\r\n\x16NEXT";
        let (stream, header) = read_header_before_tls(input.as_slice(), true)
            .await
            .unwrap();
        assert_eq!(
            header,
            ProxyHeader::Present(Some("203.0.113.10:42300".parse().unwrap()))
        );
        assert_eq!(remainder(stream).await, b"\x16NEXT");
    }

    #[tokio::test]
    async fn neither_header_nor_tls_is_rejected() {
        let error = read_header_before_tls(b"GET / HTTP/1.1\r\n".as_slice(), true)
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("invalid PROXY protocol"));
    }

    #[tokio::test]
    async fn nothing_is_read_when_the_listener_expects_no_header() {
        let input = b"PROXY UNKNOWN\r\nNEXT";
        let (stream, header) = read_header_before_tls(input.as_slice(), false)
            .await
            .unwrap();
        assert_eq!(header, ProxyHeader::NotExpected);
        assert_eq!(remainder(stream).await, input);
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
