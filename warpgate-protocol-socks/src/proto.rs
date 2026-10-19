//! The subset of SOCKS5 (RFC 1928) with username/password authentication
//! (RFC 1929) that the gateway speaks: one `CONNECT` per connection and no other
//! authentication method. Everything here is a plain function over
//! `AsyncRead`/`AsyncWrite`, so it can be tested against an in-memory stream.

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use warpgate_common::Secret;

use crate::error::SocksError;

const SOCKS_VERSION: u8 = 5;
const AUTH_VERSION: u8 = 1;
const METHOD_USERNAME_PASSWORD: u8 = 0x02;
const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// The reply codes of RFC 1928 section 6 that the gateway can send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Reply {
    Succeeded = 0x00,
    NotAllowed = 0x02,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

impl Reply {
    /// How a failed dial of the target is reported to the client.
    pub const fn for_connect_error(kind: ErrorKind) -> Self {
        match kind {
            ErrorKind::ConnectionRefused => Self::ConnectionRefused,
            ErrorKind::TimedOut => Self::TtlExpired,
            _ => Self::HostUnreachable,
        }
    }
}

/// The destination a client asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    pub destination: Destination,
    pub port: u16,
}

/// What a request resolved to: something to dial, or a reply to send instead.
#[derive(Debug, PartialEq, Eq)]
pub enum RequestOutcome {
    Connect(ConnectRequest),
    Reject(Reply),
}

pub struct Credentials {
    pub username: String,
    pub password: Secret<String>,
}

impl ConnectRequest {
    /// Whether the client asked for exactly the address the target is configured
    /// with. An IP literal is only ever equal to an IP literal and a name to a
    /// name: nothing is resolved here, since the answer authorizes the request.
    pub fn matches(&self, target_host: &str, target_port: u16) -> bool {
        if self.port != target_port {
            return false;
        }
        let target_host = strip_brackets(target_host);
        match &self.destination {
            Destination::Ip(requested) => target_host
                .parse::<IpAddr>()
                .is_ok_and(|target| target == *requested),
            Destination::Domain(requested) => {
                target_host.parse::<IpAddr>().is_err()
                    && trim_root_dot(requested).eq_ignore_ascii_case(trim_root_dot(target_host))
            }
        }
    }
}

/// `[::1]` and `::1` both name the IPv6 loopback in a target's host field.
pub fn strip_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
}

fn trim_root_dot(host: &str) -> &str {
    host.strip_suffix('.').unwrap_or(host)
}

/// Reads the client greeting and answers with the method selection. Only
/// username/password is ever selected; a client that doesn't offer it is told
/// so (`05 FF`) and [`SocksError::NoAcceptableMethod`] is returned.
pub async fn negotiate_method<S>(stream: &mut S) -> Result<(), SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    let [version, method_count] = header;
    if version != SOCKS_VERSION {
        return Err(SocksError::UnsupportedVersion(version));
    }

    let mut methods = vec![0u8; usize::from(method_count)];
    stream.read_exact(&mut methods).await?;

    if methods.contains(&METHOD_USERNAME_PASSWORD) {
        stream
            .write_all(&[SOCKS_VERSION, METHOD_USERNAME_PASSWORD])
            .await?;
        stream.flush().await?;
        Ok(())
    } else {
        stream
            .write_all(&[SOCKS_VERSION, METHOD_NONE_ACCEPTABLE])
            .await?;
        stream.flush().await?;
        Err(SocksError::NoAcceptableMethod)
    }
}

/// Reads the RFC 1929 username/password message. Anything that isn't valid UTF-8
/// is a [`SocksError::Malformed`] rather than being lossily converted into a name
/// that could collide with another user's.
pub async fn read_credentials<S>(stream: &mut S) -> Result<Credentials, SocksError>
where
    S: AsyncRead + Unpin,
{
    let version = stream.read_u8().await?;
    if version != AUTH_VERSION {
        return Err(SocksError::UnsupportedVersion(version));
    }

    let username = read_short_field(stream).await?;
    let password = read_short_field(stream).await?;

    Ok(Credentials {
        username: String::from_utf8(username)
            .map_err(|_| SocksError::Malformed("username is not UTF-8"))?,
        password: Secret::new(
            String::from_utf8(password)
                .map_err(|_| SocksError::Malformed("password is not UTF-8"))?,
        ),
    })
}

async fn read_short_field<S>(stream: &mut S) -> Result<Vec<u8>, SocksError>
where
    S: AsyncRead + Unpin,
{
    let length = stream.read_u8().await?;
    let mut field = vec![0u8; usize::from(length)];
    stream.read_exact(&mut field).await?;
    Ok(field)
}

/// The RFC 1929 status message. Every failure is the same `01 01`, so the wire
/// reveals nothing about why a login was refused.
pub async fn write_auth_status<S>(stream: &mut S, success: bool) -> Result<(), SocksError>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&[AUTH_VERSION, u8::from(!success)])
        .await?;
    stream.flush().await?;
    Ok(())
}

/// Reads a request. Only `CONNECT` is served; the command is checked before the
/// address so that `BIND` and `UDP ASSOCIATE` are refused with the right code
/// whatever address follows.
pub async fn read_request<S>(stream: &mut S) -> Result<RequestOutcome, SocksError>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let [version, command, _reserved, address_type] = header;
    if version != SOCKS_VERSION {
        return Err(SocksError::UnsupportedVersion(version));
    }
    if command != CMD_CONNECT {
        return Ok(RequestOutcome::Reject(Reply::CommandNotSupported));
    }

    let destination = match address_type {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            Destination::Ip(Ipv4Addr::from(octets).into())
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            Destination::Ip(Ipv6Addr::from(octets).into())
        }
        ATYP_DOMAIN => {
            let name = read_short_field(stream).await?;
            Destination::Domain(
                String::from_utf8(name)
                    .map_err(|_| SocksError::Malformed("domain name is not UTF-8"))?,
            )
        }
        _ => return Ok(RequestOutcome::Reject(Reply::AddressTypeNotSupported)),
    };
    let port = stream.read_u16().await?;

    Ok(RequestOutcome::Connect(ConnectRequest {
        destination,
        port,
    }))
}

/// Writes a reply. `bound` is the address the gateway's outgoing connection is
/// bound to; failures carry the all-zero IPv4 address.
pub async fn write_reply<S>(
    stream: &mut S,
    reply: Reply,
    bound: Option<SocketAddr>,
) -> Result<(), SocksError>
where
    S: AsyncWrite + Unpin,
{
    let mut message = vec![SOCKS_VERSION, reply as u8, 0];
    match bound.unwrap_or_else(|| SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))) {
        SocketAddr::V4(address) => {
            message.push(ATYP_IPV4);
            message.extend_from_slice(&address.ip().octets());
            message.extend_from_slice(&address.port().to_be_bytes());
        }
        SocketAddr::V6(address) => {
            message.push(ATYP_IPV6);
            message.extend_from_slice(&address.ip().octets());
            message.extend_from_slice(&address.port().to_be_bytes());
        }
    }
    stream.write_all(&message).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::duplex;

    use super::*;

    /// What the server wrote to a client that sent `input` and then hung up.
    async fn greet(input: &[u8]) -> (Result<(), SocksError>, Vec<u8>) {
        let (mut client, mut server) = duplex(1024);
        client.write_all(input).await.unwrap();
        client.shutdown().await.unwrap();
        let result = negotiate_method(&mut server).await;
        drop(server);
        let mut written = Vec::new();
        client.read_to_end(&mut written).await.unwrap();
        (result, written)
    }

    async fn request(mut input: &[u8]) -> Result<RequestOutcome, SocksError> {
        read_request(&mut input).await
    }

    #[tokio::test]
    async fn selects_username_password() {
        let (result, written) = greet(&[5, 3, 0, 1, 2]).await;
        result.unwrap();
        assert_eq!(written, [5, 2]);
    }

    #[tokio::test]
    async fn refuses_when_username_password_is_not_offered() {
        for greeting in [&[5, 1, 0][..], &[5, 2, 0, 1], &[5, 0]] {
            let (result, written) = greet(greeting).await;
            assert!(matches!(result, Err(SocksError::NoAcceptableMethod)));
            assert_eq!(written, [5, 0xFF], "{greeting:?}");
        }
    }

    #[tokio::test]
    async fn drops_other_protocol_versions_without_replying() {
        let (result, written) = greet(&[4, 1, 2]).await;
        assert!(matches!(result, Err(SocksError::UnsupportedVersion(4))));
        assert!(written.is_empty());
    }

    #[tokio::test]
    async fn truncated_greeting_is_an_io_error() {
        for greeting in [&[][..], &[5], &[5, 3, 2]] {
            let (result, written) = greet(greeting).await;
            assert!(matches!(result, Err(SocksError::Io(_))), "{greeting:?}");
            assert!(written.is_empty());
        }
    }

    #[tokio::test]
    async fn reads_credentials() {
        let mut input = vec![1, 5];
        input.extend_from_slice(b"alice");
        input.push(3);
        input.extend_from_slice(b"pw!");
        let credentials = read_credentials(&mut input.as_slice()).await.unwrap();
        assert_eq!(credentials.username, "alice");
        assert_eq!(credentials.password.expose_secret(), "pw!");
    }

    #[tokio::test]
    async fn reads_empty_credentials() {
        let credentials = read_credentials(&mut [1, 0, 0].as_slice()).await.unwrap();
        assert_eq!(credentials.username, "");
        assert_eq!(credentials.password.expose_secret(), "");
    }

    #[tokio::test]
    async fn rejects_bad_credential_messages() {
        assert!(matches!(
            read_credentials(&mut [2, 0, 0].as_slice()).await,
            Err(SocksError::UnsupportedVersion(2))
        ));
        // not UTF-8
        assert!(matches!(
            read_credentials(&mut [1, 1, 0xFF, 0].as_slice()).await,
            Err(SocksError::Malformed(_))
        ));
        assert!(matches!(
            read_credentials(&mut [1, 0, 1, 0xFF].as_slice()).await,
            Err(SocksError::Malformed(_))
        ));
        // truncated in every field
        for input in [
            &[1][..],
            &[1, 3, b'a'],
            &[1, 1, b'a'],
            &[1, 1, b'a', 2, b'p'],
        ] {
            assert!(
                matches!(read_credentials(&mut &*input).await, Err(SocksError::Io(_))),
                "{input:?}"
            );
        }
    }

    #[tokio::test]
    async fn auth_status_is_the_same_for_every_failure() {
        let mut ok = Vec::new();
        write_auth_status(&mut ok, true).await.unwrap();
        assert_eq!(ok, [1, 0]);
        let mut denied = Vec::new();
        write_auth_status(&mut denied, false).await.unwrap();
        assert_eq!(denied, [1, 1]);
    }

    #[tokio::test]
    async fn parses_every_address_type() {
        assert_eq!(
            request(&[5, 1, 0, 1, 10, 0, 0, 7, 0x1F, 0x90])
                .await
                .unwrap(),
            RequestOutcome::Connect(ConnectRequest {
                destination: Destination::Ip(Ipv4Addr::new(10, 0, 0, 7).into()),
                port: 8080,
            })
        );

        let mut v6 = vec![5, 1, 0, 4];
        v6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        v6.extend_from_slice(&[0, 22]);
        assert_eq!(
            request(&v6).await.unwrap(),
            RequestOutcome::Connect(ConnectRequest {
                destination: Destination::Ip(Ipv6Addr::LOCALHOST.into()),
                port: 22,
            })
        );

        let mut domain = vec![5, 1, 0, 3, 11];
        domain.extend_from_slice(b"example.com");
        domain.extend_from_slice(&[1, 187]);
        assert_eq!(
            request(&domain).await.unwrap(),
            RequestOutcome::Connect(ConnectRequest {
                destination: Destination::Domain("example.com".into()),
                port: 443,
            })
        );
    }

    #[tokio::test]
    async fn refuses_bind_and_udp_associate() {
        for command in [2, 3, 0, 0x80] {
            assert_eq!(
                request(&[5, command, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap(),
                RequestOutcome::Reject(Reply::CommandNotSupported),
                "{command}"
            );
        }
        // whatever follows the command is not needed to refuse it
        assert_eq!(
            request(&[5, 2, 0, 0x77]).await.unwrap(),
            RequestOutcome::Reject(Reply::CommandNotSupported)
        );
    }

    #[tokio::test]
    async fn refuses_unknown_address_types() {
        for address_type in [0, 2, 5, 0xFF] {
            assert_eq!(
                request(&[5, 1, 0, address_type, 1, 2, 3, 4, 0, 80])
                    .await
                    .unwrap(),
                RequestOutcome::Reject(Reply::AddressTypeNotSupported),
                "{address_type}"
            );
        }
    }

    #[tokio::test]
    async fn rejects_malformed_requests() {
        assert!(matches!(
            request(&[4, 1, 0, 1, 1, 2, 3, 4, 0, 80]).await,
            Err(SocksError::UnsupportedVersion(4))
        ));
        assert!(matches!(
            request(&[5, 1, 0, 3, 2, 0xFF, 0xFE, 0, 80]).await,
            Err(SocksError::Malformed(_))
        ));
        // truncated at every point
        let full = [5, 1, 0, 3, 3, b'a', b'b', b'c', 0, 80];
        for length in 0..full.len() {
            assert!(
                matches!(request(&full[..length]).await, Err(SocksError::Io(_))),
                "{length}"
            );
        }
    }

    #[tokio::test]
    async fn partial_reads_are_reassembled() {
        let (mut client, mut server) = duplex(64);
        let reader = tokio::spawn(async move { read_request(&mut server).await });
        let mut message = vec![5, 1, 0, 3, 9];
        message.extend_from_slice(b"localhost");
        message.extend_from_slice(&[0x1F, 0x90]);
        for byte in message {
            client.write_all(&[byte]).await.unwrap();
            client.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(
            reader.await.unwrap().unwrap(),
            RequestOutcome::Connect(ConnectRequest {
                destination: Destination::Domain("localhost".into()),
                port: 8080,
            })
        );
    }

    #[tokio::test]
    async fn writes_replies() {
        let mut out = Vec::new();
        write_reply(&mut out, Reply::NotAllowed, None)
            .await
            .unwrap();
        assert_eq!(out, [5, 2, 0, 1, 0, 0, 0, 0, 0, 0]);

        let mut out = Vec::new();
        write_reply(
            &mut out,
            Reply::Succeeded,
            Some(SocketAddr::from(([192, 0, 2, 1], 4660))),
        )
        .await
        .unwrap();
        assert_eq!(out, [5, 0, 0, 1, 192, 0, 2, 1, 0x12, 0x34]);

        let mut out = Vec::new();
        write_reply(
            &mut out,
            Reply::Succeeded,
            Some(SocketAddr::from((Ipv6Addr::LOCALHOST, 1))),
        )
        .await
        .unwrap();
        assert_eq!(out.len(), 22);
        assert_eq!(out[..4], [5, 0, 0, 4]);
    }

    #[test]
    fn connect_errors_map_to_reply_codes() {
        assert_eq!(
            Reply::for_connect_error(ErrorKind::ConnectionRefused),
            Reply::ConnectionRefused
        );
        assert_eq!(
            Reply::for_connect_error(ErrorKind::TimedOut),
            Reply::TtlExpired
        );
        for kind in [
            ErrorKind::NotFound,
            ErrorKind::Other,
            ErrorKind::HostUnreachable,
        ] {
            assert_eq!(Reply::for_connect_error(kind), Reply::HostUnreachable);
        }
    }

    fn requested(destination: Destination, port: u16) -> ConnectRequest {
        ConnectRequest { destination, port }
    }

    #[test]
    fn matches_the_configured_target_only() {
        let name = |n: &str| Destination::Domain(n.into());
        let ip = |s: &str| Destination::Ip(s.parse().unwrap());

        assert!(requested(name("db.internal"), 5432).matches("db.internal", 5432));
        assert!(requested(name("DB.Internal."), 5432).matches("db.internal", 5432));
        assert!(requested(ip("10.1.2.3"), 22).matches("10.1.2.3", 22));
        assert!(requested(ip("::1"), 22).matches("::1", 22));
        assert!(requested(ip("::1"), 22).matches("[::1]", 22));
        assert!(requested(ip("2001:db8::1"), 22).matches("2001:0db8:0:0:0:0:0:1", 22));

        // wrong port, wrong host
        assert!(!requested(name("db.internal"), 5433).matches("db.internal", 5432));
        assert!(!requested(name("other.internal"), 5432).matches("db.internal", 5432));
        assert!(!requested(ip("10.1.2.4"), 22).matches("10.1.2.3", 22));
        // a name never matches an IP literal, nor the other way round
        assert!(!requested(name("10.1.2.3"), 22).matches("10.1.2.3", 22));
        assert!(!requested(ip("10.1.2.3"), 22).matches("db.internal", 22));
        // suffixes and prefixes are not matches
        assert!(!requested(name("evil-db.internal"), 5432).matches("db.internal", 5432));
        assert!(!requested(name("db.internal.evil"), 5432).matches("db.internal", 5432));
        assert!(!requested(name("x"), 5432).matches("", 5432));
    }
}
