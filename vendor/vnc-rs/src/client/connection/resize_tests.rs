use super::*;
use crate::{DesktopReason, DesktopStatus, ResizeError, VncConnector};
use tokio::{
    io::{duplex, DuplexStream},
    time::{timeout, Duration},
};

fn update(
    reason: u16,
    status: u16,
    width: u16,
    height: u16,
    screens: &[(u32, u16, u16, u16, u16, u32)],
) -> Vec<u8> {
    let mut bytes = rect_header(
        Rect {
            x: reason,
            y: status,
            width,
            height,
        },
        VncEncoding::ExtendedDesktopSizePseudo.into(),
    );
    bytes.extend([screens.len() as u8, 0, 0, 0]);
    for &(id, x, y, w, h, flags) in screens {
        bytes.extend(id.to_be_bytes());
        for n in [x, y, w, h] {
            bytes.extend(n.to_be_bytes());
        }
        bytes.extend(flags.to_be_bytes());
    }
    bytes
}
pub(super) fn single(reason: u16, status: u16, width: u16, height: u16) -> Vec<u8> {
    update(
        reason,
        status,
        width,
        height,
        &[(42, 0, 0, width, height, 0x8000_0001)],
    )
}
pub(super) async fn extended(stream: tokio::io::DuplexStream) -> VncClient {
    crate::VncConnector::new(stream)
        .set_auth_method(async { Ok(String::new()) })
        .set_pixel_format(PixelFormat::rgba())
        .add_encoding(VncEncoding::Raw)
        .add_encoding(VncEncoding::DesktopSizePseudo)
        .add_encoding(VncEncoding::ExtendedDesktopSizePseudo)
        .add_encoding(VncEncoding::LastRectPseudo)
        .add_encoding(VncEncoding::CursorPseudo)
        .allow_shared(true)
        .build()
        .unwrap()
        .try_start()
        .await
        .unwrap()
        .finish()
        .unwrap()
}

#[tokio::test]
async fn negotiation_identity_confirmation_and_refresh_bounds() {
    let (client, mut server) = duplex(4096);
    let task = tokio::spawn(async move {
        handshake(&mut server, (80, 60)).await;
        server.write_all(&single(0, 0, 80, 60)).await.unwrap();
        let mut request = [0; 34];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(&request[24..], &[3, 1, 0, 0, 0, 0, 0, 1, 0, 1]);
        assert_eq!(&request[..8], &[251, 0, 0, 160, 0, 100, 1, 0]);
        assert_eq!(&request[8..12], &42u32.to_be_bytes());
        assert_eq!(&request[20..24], &0x8000_0001u32.to_be_bytes());
        // An unrelated layout update is not our acknowledgement.
        server.write_all(&single(2, 0, 100, 80)).await.unwrap();
        server.write_all(&single(1, 0, 160, 100)).await.unwrap();
        let mut request = [0; 10];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(request, [3, 1, 0, 0, 0, 0, 0, 160, 0, 100]);
        server.write_all(&single(0, 0, 160, 100)).await.unwrap();
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(request, [3, 1, 0, 0, 0, 0, 0, 160, 0, 100]);
        server.write_all(&single(1, 0, 80, 60)).await.unwrap();
        // Keep transport alive until the assertion caller closes normally.
        assert_eq!(server.read(&mut request).await.unwrap(), 0);
    });
    let client = extended(client).await;
    assert!(matches!(event(&client).await, VncEvent::SetResolution(_)));
    assert!(matches!(event(&client).await, VncEvent::DesktopUpdate(_)));
    let request_client = client.clone();
    let resize = tokio::spawn(async move { request_client.resize_desktop(160, 100).await });
    assert!(
        matches!(event(&client).await,VncEvent::DesktopUpdate(u) if u.reason==DesktopReason::OtherClient)
    );
    assert!(
        matches!(event(&client).await,VncEvent::DesktopUpdate(u) if u.reason==DesktopReason::ThisClient)
    );
    assert_eq!(resize.await.unwrap().unwrap().width, 160);
    client.input(X11Event::Refresh).await.unwrap();
    assert!(matches!(event(&client).await, VncEvent::DesktopUpdate(_)));
    // Same-size requests dispatch nothing and leave the next request incremental.
    assert_eq!(client.resize_desktop(160, 100).await.unwrap().height, 100);
    client.input(X11Event::Refresh).await.unwrap();
    assert!(matches!(event(&client).await, VncEvent::DesktopUpdate(_)));
    client.close().await.unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn unsupported_server_never_receives_resize_bytes() {
    let (stream, mut server) = duplex(4096);
    let (ready, wait) = oneshot::channel();
    let task = tokio::spawn(async move {
        handshake(&mut server, (80, 60)).await;
        ready.send(()).unwrap();
        let mut byte = [0];
        assert_eq!(server.read(&mut byte).await.unwrap(), 0);
    });
    let client = connect(stream).await;
    wait.await.unwrap();
    assert_eq!(
        client.resize_desktop(160, 100).await,
        Err(ResizeError::Unsupported)
    );
    client.close().await.unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn rejected_and_forwarded_replies_do_not_apply_undefined_geometry() {
    for (status, expected) in [
        (1, ResizeError::Denied(DesktopStatus::Prohibited)),
        (256, ResizeError::Denied(DesktopStatus::Unknown(256))),
        (4, ResizeError::Uncertain),
    ] {
        let (stream, mut server) = duplex(4096);
        let task = tokio::spawn(async move {
            handshake(&mut server, (80, 60)).await;
            server.write_all(&single(0, 0, 80, 60)).await.unwrap();
            let mut request = [0; 34];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[24..], &[3, 1, 0, 0, 0, 0, 0, 1, 0, 1]);
            server
                .write_all(&update(1, status, 0, 65535, &[]))
                .await
                .unwrap();
            let mut b = [0];
            assert_eq!(server.read(&mut b).await.unwrap(), 0);
        });
        let client = extended(stream).await;
        event(&client).await;
        event(&client).await;
        assert_eq!(client.resize_desktop(160, 100).await, Err(expected));
        assert_eq!(client.desktop_layout().unwrap().width, 80);
        assert!(matches!(event(&client).await,VncEvent::DesktopUpdate(u) if u.layout.is_none()));
        client.close().await.unwrap();
        task.await.unwrap();
    }
}

#[tokio::test]
async fn malformed_layouts_fail_but_unknown_reason_is_not_a_client_ack() {
    for packet in [
        single(0, 0, 0, 60),
        single(0, 0, 8192, 8192),
        update(0, 0, 80, 60, &[(1, 70, 0, 20, 60, 0)]),
        update(0, 0, 80, 60, &[(1, 0, 0, 80, 60, 0), (1, 0, 0, 80, 60, 0)]),
    ] {
        let (stream, mut server) = duplex(4096);
        let task = tokio::spawn(async move {
            handshake(&mut server, (80, 60)).await;
            server.write_all(&packet).await.unwrap();
            let mut b = [0];
            let _ = server.read(&mut b).await;
        });
        let client = extended(stream).await;
        event(&client).await;
        assert!(matches!(event(&client).await, VncEvent::Error(_)));
        client.close().await.unwrap();
        task.await.unwrap();
    }
    let packet = single(257, 65535, 80, 60);
    let u = crate::DesktopUpdate::read(
        &mut &packet[16..],
        Rect {
            x: 257,
            y: 65535,
            width: 80,
            height: 60,
        },
    )
    .await
    .unwrap();
    assert_eq!(u.reason, DesktopReason::Unknown(257));
    assert_eq!(u.status, DesktopStatus::Success);
}

#[tokio::test]
async fn cancellation_stalled_reply_and_concurrency_are_bounded() {
    let (stream, mut server) = duplex(4096);
    let (sent, received) = oneshot::channel();
    let task = tokio::spawn(async move {
        handshake(&mut server, (80, 60)).await;
        server.write_all(&single(0, 0, 80, 60)).await.unwrap();
        let mut request = [0; 34];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(&request[24..], &[3, 1, 0, 0, 0, 0, 0, 1, 0, 1]);
        sent.send(()).unwrap();
        // Start an incomplete layout payload to exercise decoder cancellation too.
        server
            .write_all(&single(1, 0, 160, 100)[..18])
            .await
            .unwrap();
        let mut b = [0];
        assert_eq!(server.read(&mut b).await.unwrap(), 0);
    });
    let client = extended(stream).await;
    event(&client).await;
    event(&client).await;
    assert_eq!(
        client.resize_desktop(8192, 8192).await,
        Err(ResizeError::InvalidDimensions)
    );
    let other = client.clone();
    let request = tokio::spawn(async move { other.resize_desktop(160, 100).await });
    received.await.unwrap();
    assert_eq!(client.resize_desktop(120, 80).await, Err(ResizeError::Busy));
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    assert_eq!(
        client.resize_desktop(160, 100).await,
        Err(ResizeError::Uncertain)
    );
    timeout(Duration::from_secs(1), client.close())
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn multi_screen_layout_is_preserved_and_refused_without_dispatch() {
    let (stream, mut server) = duplex(4096);
    let task = tokio::spawn(async move {
        handshake(&mut server, (80, 60)).await;
        server
            .write_all(&update(
                0,
                0,
                80,
                60,
                &[(1, 0, 0, 40, 60, 7), (2, 40, 0, 40, 60, 9)],
            ))
            .await
            .unwrap();
        let mut b = [0];
        assert_eq!(server.read(&mut b).await.unwrap(), 0);
    });
    let client = extended(stream).await;
    event(&client).await;
    event(&client).await;
    assert_eq!(client.desktop_layout().unwrap().screens.len(), 2);
    assert_eq!(
        client.resize_desktop(160, 100).await,
        Err(ResizeError::UnsupportedLayout)
    );
    client.close().await.unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn timeout_and_disconnect_never_report_dispatch_as_success() {
    for disconnect in [true, false] {
        let (stream, mut server) = duplex(4096);
        let task = tokio::spawn(async move {
            handshake(&mut server, (80, 60)).await;
            server.write_all(&single(0, 0, 80, 60)).await.unwrap();
            let mut request = [0; 34];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[24..], &[3, 1, 0, 0, 0, 0, 0, 1, 0, 1]);
            if !disconnect {
                let mut b = [0];
                assert_eq!(server.read(&mut b).await.unwrap(), 0);
            }
        });
        let client = extended(stream).await;
        event(&client).await;
        event(&client).await;
        let expected = if disconnect {
            ResizeError::Uncertain
        } else {
            ResizeError::Timeout
        };
        assert_eq!(
            timeout(Duration::from_secs(6), client.resize_desktop(160, 100))
                .await
                .unwrap(),
            Err(expected)
        );
        if !disconnect {
            assert_eq!(
                client.resize_desktop(160, 100).await,
                Err(ResizeError::Uncertain)
            );
        }
        assert_eq!(client.desktop_layout().unwrap().width, 80);
        client.close().await.unwrap();
        task.await.unwrap();
    }
}

#[tokio::test]
async fn mixed_framebuffer_updates_cannot_confirm_a_resize() {
    for pixels_first in [true, false] {
        let (stream, mut server) = duplex(4096);
        let task = tokio::spawn(async move {
            handshake(&mut server, (80, 60)).await;
            server.write_all(&single(0, 0, 80, 60)).await.unwrap();
            let mut request = [0; 34];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[24..], &[3, 1, 0, 0, 0, 0, 0, 1, 0, 1]);
            let extended = single(1, 0, 160, 100);
            let mut raw = rect_header(
                Rect {
                    x: 0,
                    y: 0,
                    width: 1,
                    height: 1,
                },
                0,
            );
            raw.extend([1, 2, 3, 0]);
            let mut mixed = vec![0, 0, 0, 2];
            if pixels_first {
                mixed.extend(&raw[4..]);
                mixed.extend(&extended[4..]);
            } else {
                mixed.extend(&extended[4..]);
                mixed.extend(&raw[4..]);
            }
            server.write_all(&mixed).await.unwrap();
            let mut b = [0];
            let _ = server.read(&mut b).await;
        });
        let client = extended(stream).await;
        event(&client).await;
        event(&client).await;
        assert_eq!(
            client.resize_desktop(160, 100).await,
            Err(ResizeError::Uncertain)
        );
        assert_eq!(client.desktop_layout().unwrap().width, 80);
        client.close().await.unwrap();
        task.await.unwrap();
    }
}

#[tokio::test]
async fn last_rect_sentinel_bounds_actual_layouts_not_declared_count() {
    let (stream, mut server) = duplex(4096);
    let task = tokio::spawn(async move {
        handshake(&mut server, (80, 60)).await;
        let mut packet = single(0, 0, 80, 60);
        packet[2..4].copy_from_slice(&u16::MAX.to_be_bytes());
        let last = rect_header(
            Rect {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            },
            VncEncoding::LastRectPseudo.into(),
        );
        packet.extend(&last[4..]);
        server.write_all(&packet).await.unwrap();
        let mut b = [0];
        let _ = server.read(&mut b).await;
    });
    let client = extended(stream).await;
    event(&client).await;
    assert!(matches!(event(&client).await, VncEvent::DesktopUpdate(_)));
    assert_eq!(client.desktop_layout().unwrap().width, 80);
    client.close().await.unwrap();
    task.await.unwrap();
}

pub(super) async fn handshake(server: &mut DuplexStream, size: (u16, u16)) {
    handshake_named(server, size, "test").await;
}

pub(super) async fn handshake_named(server: &mut DuplexStream, size: (u16, u16), name: &str) {
    server.write_all(b"RFB 003.008\n").await.unwrap();
    let mut version = [0; 12];
    server.read_exact(&mut version).await.unwrap();
    assert_eq!(&version, b"RFB 003.008\n");
    server.write_all(&[1, 1]).await.unwrap();
    assert_eq!(server.read_u8().await.unwrap(), 1);
    server.write_u32(0).await.unwrap();
    assert_eq!(server.read_u8().await.unwrap(), 1);
    server.write_u16(size.0).await.unwrap();
    server.write_u16(size.1).await.unwrap();
    server
        .write_all(&Vec::<u8>::from(PixelFormat::rgba()))
        .await
        .unwrap();
    server.write_u32(name.len() as u32).await.unwrap();
    server.write_all(name.as_bytes()).await.unwrap();
    let mut pixel_format = [0; 20];
    server.read_exact(&mut pixel_format).await.unwrap();
    assert_eq!(pixel_format[0], 0);
    assert_eq!(server.read_u8().await.unwrap(), 2);
    server.read_u8().await.unwrap();
    let count = server.read_u16().await.unwrap();
    for _ in 0..count {
        server.read_u32().await.unwrap();
    }
    let mut request = [0; 10];
    server.read_exact(&mut request).await.unwrap();
    assert_eq!(request[0], 3);
}

pub(super) async fn connect(stream: DuplexStream) -> VncClient {
    VncConnector::new(stream)
        .set_auth_method(async { Ok("test".to_string()) })
        .set_pixel_format(PixelFormat::rgba())
        .add_encoding(VncEncoding::Raw)
        .add_encoding(VncEncoding::CopyRect)
        .add_encoding(VncEncoding::Zrle)
        .add_encoding(VncEncoding::DesktopSizePseudo)
        .build()
        .unwrap()
        .try_start()
        .await
        .unwrap()
        .finish()
        .unwrap()
}

pub(super) async fn event(client: &VncClient) -> VncEvent {
    tokio::time::timeout(Duration::from_secs(2), client.recv_event())
        .await
        .unwrap()
        .unwrap()
}

pub(super) fn rect_header(rect: Rect, encoding: u32) -> Vec<u8> {
    let mut bytes = vec![0, 0, 0, 1];
    for value in [rect.x, rect.y, rect.width, rect.height] {
        bytes.extend(value.to_be_bytes());
    }
    bytes.extend(encoding.to_be_bytes());
    bytes
}

#[tokio::test]
async fn cursor_metadata_can_precede_or_follow_resize_confirmation() {
    for cursor_first in [false, true] {
        let (stream, mut server) = duplex(4096);
        let task = tokio::spawn(async move {
            handshake(&mut server, (80, 60)).await;
            server.write_all(&single(0, 0, 80, 60)).await.unwrap();
            let mut request = [0; 34];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[24..], &[3, 1, 0, 0, 0, 0, 0, 1, 0, 1]);
            let mut cursor = rect_header(
                Rect {
                    x: 0,
                    y: 0,
                    width: 1,
                    height: 1,
                },
                VncEncoding::CursorPseudo.into(),
            );
            cursor.extend([10, 20, 30, 0, 128]);
            let layout = single(1, 0, 160, 100);
            let mut packet = vec![0, 0, 0, 2];
            for bytes in if cursor_first {
                [&cursor, &layout]
            } else {
                [&layout, &cursor]
            } {
                packet.extend_from_slice(&bytes[4..]);
            }
            server.write_all(&packet).await.unwrap();
            let mut byte = [0];
            assert_eq!(server.read(&mut byte).await.unwrap(), 0);
        });
        let client = extended(stream).await;
        event(&client).await;
        event(&client).await;
        assert_eq!(client.resize_desktop(160, 100).await.unwrap().width, 160);
        assert!(
            matches!(event(&client).await, VncEvent::SetCursor(rect, data) if rect.width == 1 && data == [10, 20, 30, 255])
        );
        assert!(
            matches!(event(&client).await, VncEvent::DesktopUpdate(update) if update.reason == DesktopReason::ThisClient)
        );
        client.close().await.unwrap();
        task.await.unwrap();
    }
}

#[tokio::test]
async fn queued_layouts_confirm_only_after_the_complete_batch_then_decode_pixels() {
    let (stream, mut server) = duplex(8192);
    let (staged, staged_rx) = oneshot::channel();
    let (finish, finish_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        handshake(&mut server, (80, 60)).await;
        server.write_all(&single(0, 0, 80, 60)).await.unwrap();
        let mut request = [0; 34];
        server.read_exact(&mut request).await.unwrap();
        let mut packet = vec![0, 0, 0, 34];
        packet.extend(&single(1, 0, 160, 100)[4..]);
        for index in 0..32 {
            packet.extend(&single(index % 2 * 2, 0, 160, 100)[4..]);
        }
        server.write_all(&packet).await.unwrap();
        staged.send(()).unwrap();
        finish_rx.await.unwrap();
        server
            .write_all(&single(2, 0, 160, 100)[4..])
            .await
            .unwrap();
        let mut raw = rect_header(
            Rect {
                x: 159,
                y: 99,
                width: 1,
                height: 1,
            },
            0,
        );
        raw.extend([1, 2, 3, 0]);
        server.write_all(&raw).await.unwrap();
        let mut byte = [0];
        let _ = server.read(&mut byte).await;
    });
    let client = extended(stream).await;
    event(&client).await;
    event(&client).await;
    let request_client = client.clone();
    let mut request = tokio::spawn(async move { request_client.resize_desktop(160, 100).await });
    staged_rx.await.unwrap();
    assert!(timeout(Duration::from_millis(50), &mut request)
        .await
        .is_err());
    assert_eq!(client.desktop_layout().unwrap().width, 80);
    finish.send(()).unwrap();
    assert_eq!(request.await.unwrap().unwrap().width, 160);
    for index in 0..34 {
        let VncEvent::DesktopUpdate(update) = event(&client).await else {
            panic!("layout expected")
        };
        let expected = if index == 0 {
            DesktopReason::ThisClient
        } else if index % 2 == 1 && index != 33 {
            DesktopReason::Server
        } else {
            DesktopReason::OtherClient
        };
        assert_eq!(update.reason, expected);
    }
    assert!(
        matches!(event(&client).await, VncEvent::RawImage(rect, _) if rect.x == 159 && rect.y == 99)
    );
    client.close().await.unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn invalid_or_excessive_queued_layouts_never_publish_or_confirm() {
    for excessive in [false, true] {
        let (stream, mut server) = duplex(8192);
        let task = tokio::spawn(async move {
            handshake(&mut server, (80, 60)).await;
            server.write_all(&single(0, 0, 80, 60)).await.unwrap();
            let mut request = [0; 34];
            server.read_exact(&mut request).await.unwrap();
            let count = if excessive { 1100_u16 } else { 34 };
            let mut packet = vec![0, 0];
            packet.extend(count.to_be_bytes());
            packet.extend(&single(1, 0, 160, 100)[4..]);
            let screens: Vec<_> = (0..255).map(|id| (id, 0, 0, 160, 100, 0)).collect();
            let queued = if excessive {
                update(2, 0, 160, 100, &screens)
            } else {
                single(2, 0, 160, 100)
            };
            for _ in 1..count - 1 {
                packet.extend(&queued[4..]);
            }
            packet.extend(&single(2, 0, if excessive { 160 } else { 0 }, 100)[4..]);
            // Budget exhaustion closes the reader before the full payload is consumed.
            let _ = server.write_all(&packet).await;
            let mut byte = [0];
            let _ = server.read(&mut byte).await;
        });
        let client = extended(stream).await;
        event(&client).await;
        event(&client).await;
        assert_eq!(
            client.resize_desktop(160, 100).await,
            Err(ResizeError::Uncertain)
        );
        assert_eq!(client.desktop_layout().unwrap().width, 80);
        assert!(matches!(event(&client).await, VncEvent::Error(_)));
        client.close().await.unwrap();
        task.await.unwrap();
    }
}
