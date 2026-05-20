use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

pub async fn detect_port_knock(stream: &TcpStream) -> bool {
    let mut buf = [0u8; 1];
    match timeout(Duration::from_millis(500), stream.peek(&mut buf)).await {
        // Closed
        Ok(Ok(0) | Err(_)) => {
            debug!("Client closed connection immediately");
            true
        }
        // Data or still open
        Ok(Ok(_)) | Err(_) => false,
    }
}
