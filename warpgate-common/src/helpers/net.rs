use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, warn};

use super::proxy_protocol::remote_address;

/// A connection that sends nothing for this long after accept() or PROXY header
/// is assumed to be a port knock / LB test
const KNOCK_TIMEOUT: Duration = Duration::from_millis(1000);

/// Connection setup for a freshly accept()'ed stream. If proxy_protocol
/// is on, reads the header.
///
/// Returns None if the connection was a port knock
pub async fn accept_client(stream: &mut TcpStream, proxy_protocol: bool) -> Option<SocketAddr> {
    let _ = stream.set_nodelay(true);

    if is_closed(stream, KNOCK_TIMEOUT).await {
        return None;
    }

    let address = match remote_address(stream, proxy_protocol).await {
        Ok(address) => address,
        Err(error) => {
            warn!(%error, "Failed to read PROXY protocol header");
            return None;
        }
    };

    // A HAProxy health check sends the header and closes the connection.
    // Its FIN arrives together with the header, so we don't need to wait
    if proxy_protocol && is_closed(stream, Duration::ZERO).await {
        return None;
    }

    Some(address)
}

/// Wait for up to `budget` for the stream to send something
/// If it sends nothing, assume it is a knock and return true
async fn is_closed(stream: &TcpStream, budget: Duration) -> bool {
    let mut buf = [0u8; 1];
    match timeout(budget, stream.peek(&mut buf)).await {
        // Closed
        Ok(Ok(0) | Err(_)) => {
            debug!("Client closed connection immediately");
            true
        }
        // Data or still open
        Ok(Ok(_)) | Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    use super::*;

    const V1_HEADER: &[u8] = b"PROXY TCP4 1.2.3.4 5.6.7.8 1111 2222\r\n";

    /// Runs `accept_client` against a client that writes `payload` and then hangs up
    /// unless `keep_open` holds it.
    async fn accept(payload: &'static [u8], keep_open: bool) -> Option<SocketAddr> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(address).await.unwrap();
            stream.write_all(payload).await.unwrap();
            stream.flush().await.unwrap();
            if keep_open {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        let (mut stream, _) = listener.accept().await.unwrap();
        let result = accept_client(&mut stream, true).await;
        client.abort();
        result
    }

    /// A health check behind `send-proxy` sends a complete header and closes.
    #[tokio::test]
    async fn header_then_close_is_a_knock() {
        assert_eq!(accept(V1_HEADER, false).await, None);
    }

    #[tokio::test]
    async fn header_then_protocol_data_is_a_client() {
        let payload = b"PROXY TCP4 1.2.3.4 5.6.7.8 1111 2222\r\nSSH-2.0-Test\r\n";
        assert!(accept(payload, true).await.is_some());
    }

    /// A client that has nothing to say yet (server-speaks-first protocols).
    #[tokio::test]
    async fn header_then_silence_is_a_client() {
        assert!(accept(V1_HEADER, true).await.is_some());
    }

    #[tokio::test]
    async fn bare_connect_and_close_is_a_knock() {
        assert_eq!(accept(b"", false).await, None);
    }
}
