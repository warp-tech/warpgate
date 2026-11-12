use std::net::SocketAddr;

use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use warpgate_common::GlobalParams;

use crate::config::load_config;

pub async fn command(params: &GlobalParams) -> Result<()> {
    let config = load_config(params, true)?;

    let listen_address = config.store.http.listen.address();
    let address = if config.store.http.proxy_protocol {
        proxy_protocol_relay(listen_address).await?
    } else {
        listen_address
    };

    let url = format!("https://{address}/@warpgate/api/info");

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .use_rustls_tls()
        .build()?;

    let response = timeout(std::time::Duration::from_secs(5), client.get(&url).send())
        .await
        .context("Timeout")?
        .context("Failed to send request")?;

    response.error_for_status()?;

    Ok(())
}

/// The listener expects a PROXY header before TLS, so relay the request through
/// a local socket that prepends one (UNKNOWN = "use the peer address").
async fn proxy_protocol_relay(target: SocketAddr) -> Result<SocketAddr> {
    let mut upstream = TcpStream::connect(target)
        .await
        .context("Failed to connect to the HTTP listener")?;
    upstream.write_all(b"PROXY UNKNOWN\r\n").await?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let relay_address = listener.local_addr()?;
    tokio::spawn(async move {
        if let Ok((mut client, _)) = listener.accept().await {
            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        }
    });
    Ok(relay_address)
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;
    use warpgate_common::helpers::proxy_protocol::remote_address;

    use super::*;

    #[tokio::test]
    async fn relay_prepends_proxy_header() {
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay = proxy_protocol_relay(server.local_addr().unwrap())
            .await
            .unwrap();
        let (mut upstream, peer) = server.accept().await.unwrap();

        let mut client = TcpStream::connect(relay).await.unwrap();
        client.write_all(b"hello").await.unwrap();

        // Parsed by the same code as the HTTP listener; UNKNOWN falls back to the peer
        assert_eq!(remote_address(&mut upstream, true).await.unwrap(), peer);
        let mut payload = [0u8; 5];
        upstream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"hello");
    }
}
