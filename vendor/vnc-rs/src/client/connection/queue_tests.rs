use super::*;
use std::time::Duration;
use tokio::io::duplex;

#[tokio::test]
async fn decoder_error_releases_network_before_output_drains() {
    let (stream, mut server) = duplex(256);
    server.write_u16(1).await.unwrap();
    server.write_u16(1).await.unwrap();
    server
        .write_all(&Vec::<u8>::from(PixelFormat::rgba()))
        .await
        .unwrap();
    server.write_u32(0).await.unwrap();
    let client = VncClient::new(stream, true, None, vec![VncEncoding::Raw])
        .await
        .unwrap();
    // ClientInit, SetEncodings and the initial FramebufferUpdateRequest.
    tokio::time::timeout(Duration::from_secs(1), server.read_exact(&mut [0; 19]))
        .await
        .unwrap()
        .unwrap();
    {
        let inner = client.inner.lock().await;
        assert_eq!(inner.input_ch.max_capacity(), 4096);
        assert_eq!(inner.output_ch.max_capacity(), 2);
        assert_eq!(inner.output_ch.len(), 2);
    }
    server.write_all(&[1]).await.unwrap(); // unsupported SetColorMapEntries
                                           // The decoder must release the socket even while its error cannot be queued.
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), server.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        assert!(matches!(
            client.recv_event().await.unwrap(),
            VncEvent::SetResolution(_)
        ));
        assert!(matches!(
            client.recv_event().await.unwrap(),
            VncEvent::SetPixelFormat(_)
        ));
        assert!(matches!(
            client.recv_event().await.unwrap(),
            VncEvent::Error(_)
        ));
        assert!(matches!(
            client.recv_event().await,
            Err(VncError::ClientNotRunning)
        ));
    })
    .await
    .unwrap();
    client.close().await.unwrap();
}
