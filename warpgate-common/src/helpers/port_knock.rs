//! Client-side port knocking, sent to a target host before connecting to it.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::{TcpStream, UdpSocket, lookup_host};
use tokio::time::{sleep, timeout};
use tracing::debug;

use crate::config::{PortKnockProtocol, PortKnocking};

pub const MAX_SEQUENCE_LENGTH: usize = 32;
pub const MAX_DELAY_MS: u32 = 10_000;
pub const MAX_WAIT_AFTER_MS: u32 = 30_000;

/// How long a TCP knock waits for the SYN to be answered. A knock daemon
/// usually drops the packet, so the attempt is expected to time out.
const TCP_KNOCK_TIMEOUT: Duration = Duration::from_millis(100);

/// Sends the knock sequence to `host`, then waits `wait_after_ms`.
///
/// Only the first resolved address is knocked, so that the whole sequence
/// reaches the same machine. The connection that follows should resolve to
/// the same address for the knock to be useful.
///
/// The limits from the API schema are enforced here too, since the config
/// file and the database are not validated against it.
pub async fn knock(host: &str, config: &PortKnocking) -> io::Result<()> {
    validate(config)?;

    let address = lookup_host((host, 0)).await?.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("port knocking: could not resolve {host}"),
        )
    })?;

    let delay = Duration::from_millis(config.delay_ms.min(MAX_DELAY_MS).into());
    let wait_after = Duration::from_millis(config.wait_after_ms.min(MAX_WAIT_AFTER_MS).into());

    debug!(
        %host,
        address = %address.ip(),
        knocks = config.sequence.len(),
        "Port knocking before connecting"
    );

    for (index, step) in config.sequence.iter().enumerate() {
        if index > 0 {
            sleep(delay).await;
        }
        let target = SocketAddr::new(address.ip(), step.port);
        debug!(port = step.port, protocol = ?step.protocol, "Sending knock");
        match step.protocol {
            PortKnockProtocol::Tcp => knock_tcp(target).await,
            PortKnockProtocol::Udp => knock_udp(target).await?,
        }
    }

    sleep(wait_after).await;
    Ok(())
}

fn validate(config: &PortKnocking) -> io::Result<()> {
    let length = config.sequence.len();
    if length == 0 || length > MAX_SEQUENCE_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "port knocking: the sequence must contain between 1 and {MAX_SEQUENCE_LENGTH} knocks, got {length}"
            ),
        ));
    }
    if config.sequence.iter().any(|step| step.port == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "port knocking: port 0 is not allowed",
        ));
    }
    Ok(())
}

/// The outcome does not matter: the SYN reaching the host is the knock.
async fn knock_tcp(target: SocketAddr) {
    let _ = timeout(TCP_KNOCK_TIMEOUT, TcpStream::connect(target)).await;
}

async fn knock_udp(target: SocketAddr) -> io::Result<()> {
    let local: SocketAddr = match target {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(local).await?;
    socket.send_to(&[0], target).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    use super::*;
    use crate::config::PortKnock;

    fn config(sequence: Vec<PortKnock>) -> PortKnocking {
        PortKnocking {
            sequence,
            delay_ms: 50,
            wait_after_ms: 0,
        }
    }

    #[tokio::test]
    async fn knocks_arrive_in_order() {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tcp_port = tcp.local_addr().unwrap().port();
        let udp_port = udp.local_addr().unwrap().port();

        let received = Arc::new(Mutex::new(Vec::new()));

        let tcp_task = tokio::spawn({
            let received = received.clone();
            async move {
                for _ in 0..2 {
                    let _ = tcp.accept().await.unwrap();
                    received.lock().await.push(PortKnockProtocol::Tcp);
                }
            }
        });
        let udp_task = tokio::spawn({
            let received = received.clone();
            async move {
                let mut buf = [0u8; 8];
                let (len, _) = udp.recv_from(&mut buf).await.unwrap();
                assert_eq!(len, 1);
                received.lock().await.push(PortKnockProtocol::Udp);
            }
        });

        let sequence = vec![
            PortKnock {
                port: tcp_port,
                protocol: PortKnockProtocol::Tcp,
            },
            PortKnock {
                port: udp_port,
                protocol: PortKnockProtocol::Udp,
            },
            PortKnock {
                port: tcp_port,
                protocol: PortKnockProtocol::Tcp,
            },
        ];
        knock("127.0.0.1", &config(sequence)).await.unwrap();

        timeout(Duration::from_secs(5), async {
            tcp_task.await.unwrap();
            udp_task.await.unwrap();
        })
        .await
        .unwrap();

        assert_eq!(
            *received.lock().await,
            vec![
                PortKnockProtocol::Tcp,
                PortKnockProtocol::Udp,
                PortKnockProtocol::Tcp,
            ]
        );
    }

    #[tokio::test]
    async fn closed_tcp_port_is_not_an_error() {
        // Grab a free port, then close it so the knock is refused.
        let port = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let sequence = vec![PortKnock {
            port,
            protocol: PortKnockProtocol::Tcp,
        }];
        knock("127.0.0.1", &config(sequence)).await.unwrap();
    }

    #[tokio::test]
    async fn rejects_empty_sequence() {
        let error = knock("127.0.0.1", &config(vec![])).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn rejects_too_long_sequence() {
        let sequence = vec![
            PortKnock {
                port: 1,
                protocol: PortKnockProtocol::Udp,
            };
            MAX_SEQUENCE_LENGTH + 1
        ];
        let error = knock("127.0.0.1", &config(sequence)).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn rejects_port_zero() {
        let sequence = vec![PortKnock {
            port: 0,
            protocol: PortKnockProtocol::Tcp,
        }];
        let error = knock("127.0.0.1", &config(sequence)).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
