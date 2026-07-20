use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;

use crate::Result;
use crate::generator::NetworkRequest;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Http,
    Https,
}

impl NetworkProtocol {
    pub const ALL: &'static [Self] = &[Self::Tcp, Self::Udp, Self::Http, Self::Https];

    pub(crate) fn from_url_scheme(scheme: &str) -> Option<Self> {
        match scheme {
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            "http" => Some(Self::Http),
            "https" => Some(Self::Https),
            _ => None,
        }
    }
}

/// Represents an abstract asynchronous network client.
///
/// This trait is primarily used for implementing network clients for WASM target
/// and in other cases where a synchronous network client is not an option.
pub trait AsyncNetworkClient: Send + Sync {
    /// Send request to the server and return the response.
    ///
    /// URL scheme is guaranteed to be the same as specified by `protocol` argument.
    /// `sspi-rs` will call this method only if `NetworkClient::is_protocol_supported`
    /// returned true prior to the call, so unsupported `protocol` values could be marked as `unreachable!`.
    fn send<'a>(
        &'a mut self,
        network_request: &'a NetworkRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + 'a>>;
}

pub trait NetworkClient: Send + Sync {
    /// Send request to the server and return the response. URL scheme is guaranteed to be
    /// the same as specified by `protocol` argument. `sspi-rs` will call this method only if
    /// `NetworkClient::is_protocol_supported` returned true prior to the call, so unsupported
    /// `protocol` values could be marked as `unreachable!`.
    fn send(&self, request: &NetworkRequest) -> Result<Vec<u8>>;
}

#[cfg(feature = "network_client")]
pub mod reqwest_network_client {
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, TcpStream, ToSocketAddrs, UdpSocket};
    use std::time::Duration;

    use byteorder::{BigEndian, ReadBytesExt};
    use url::Url;

    use super::{NetworkClient, NetworkProtocol};
    use crate::generator::NetworkRequest;
    use crate::{Error, ErrorKind, Result};

    // Per-KDC connection timeout. MIT krb5 defaults to 3s; Windows uses 5s.
    const KDC_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

    #[derive(Debug, Clone, Default)]
    pub struct ReqwestNetworkClient;

    impl ReqwestNetworkClient {
        fn send_tcp(&self, url: &Url, data: &[u8]) -> Result<Vec<u8>> {
            let addr = format!("{}:{}", url.host_str().unwrap_or_default(), url.port().unwrap_or(88));
            let addrs = addr
                .to_socket_addrs()
                .map_err(|e| Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{e:?}")))?;
            let mut last_err = Error::new(
                ErrorKind::NoAuthenticatingAuthority,
                "no KDC addresses to connect to".to_owned(),
            );
            let mut connected = None;
            for addr in addrs {
                debug!(%addr, "attempting KDC TCP connect");
                match TcpStream::connect_timeout(&addr, KDC_CONNECT_TIMEOUT) {
                    Ok(s) => {
                        debug!(%addr, "KDC TCP connect succeeded");
                        connected = Some(s);
                        break;
                    }
                    Err(e) => {
                        debug!(%addr, error = %e, "KDC TCP connect failed");
                        last_err = Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{e:?}"));
                    }
                }
            }
            let mut stream = connected.ok_or(last_err)?;

            stream
                .write(data)
                .map_err(|e| Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{e:?}")))?;

            let len = stream
                .read_u32::<BigEndian>()
                .map_err(|e| Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{e:?}")))?;

            let mut buf = vec![0; len as usize + 4];
            buf[0..4].copy_from_slice(&(len.to_be_bytes()));

            stream
                .read_exact(&mut buf[4..])
                .map_err(|e| Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{e:?}")))?;

            Ok(buf)
        }

        fn send_udp(&self, url: &Url, data: &[u8]) -> Result<Vec<u8>> {
            let port =
                portpicker::pick_unused_port().ok_or_else(|| Error::new(ErrorKind::InternalError, "No free ports"))?;
            let udp_socket = UdpSocket::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), port))?;
            udp_socket
                .set_read_timeout(Some(KDC_CONNECT_TIMEOUT))
                .map_err(|e| Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{e:?}")))?;

            let addr = format!("{}:{}", url.host_str().unwrap_or_default(), url.port().unwrap_or(88));
            udp_socket
                .send_to(data, addr)
                .map_err(|e| Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{e:?}")))?;

            // 48 000 bytes: default maximum token len in Windows
            let mut buf = vec![0; 0xbb80];

            let n = udp_socket
                .recv(&mut buf)
                .map_err(|e| Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{e:?}")))?;

            let mut reply_buf = Vec::with_capacity(n + 4);
            reply_buf.extend_from_slice(&(n as u32).to_be_bytes());
            reply_buf.extend_from_slice(&buf[0..n]);

            Ok(reply_buf)
        }

        fn send_http(&self, url: &Url, data: &[u8]) -> Result<Vec<u8>> {
            crate::rustls::install_default_crypto_provider_if_necessary().map_err(|()| {
                Error::new(
                    ErrorKind::SecurityPackageNotFound,
                    "failed to install the default crypto provider for TLS",
                )
            })?;

            let client = crate::rustls::load_native_certs(reqwest::blocking::ClientBuilder::new())
                .build()
                .map_err(|e| {
                    let mut msg = String::from("failed to build reqwest client: ");
                    crate::utils::write_error_chain(&mut msg, &e).expect("writing to a String is infallible");
                    Error::new(ErrorKind::NoAuthenticatingAuthority, msg)
                })?;

            let response = client
                .post(url.clone())
                .body(data.to_vec())
                .send()
                .map_err(|err| match err {
                    err if err.to_string().to_lowercase().contains("certificate") => Error::new(
                        ErrorKind::CertificateUnknown,
                        format!("Invalid certificate data: {err:?}"),
                    ),
                    _ => Error::new(
                        ErrorKind::NoAuthenticatingAuthority,
                        format!("Unable to send the data to the KDC Proxy: {err:?}"),
                    ),
                })?
                .error_for_status()
                .map_err(|err| Error::new(ErrorKind::NoAuthenticatingAuthority, format!("KDC Proxy: {err}")))?;

            let body = response.bytes().map_err(|err| {
                Error::new(
                    ErrorKind::NoAuthenticatingAuthority,
                    format!("Unable to read the response data from the KDC Proxy: {err:?}"),
                )
            })?;

            // The type bytes::Bytes has a special From implementation for Vec<u8>.
            let body = Vec::from(body);

            Ok(body)
        }
    }

    impl NetworkClient for ReqwestNetworkClient {
        fn send(&self, request: &NetworkRequest) -> Result<Vec<u8>> {
            match request.protocol {
                NetworkProtocol::Tcp => self.send_tcp(&request.url, &request.data),
                NetworkProtocol::Udp => self.send_udp(&request.url, &request.data),
                NetworkProtocol::Http | NetworkProtocol::Https => self.send_http(&request.url, &request.data),
            }
        }
    }
}
