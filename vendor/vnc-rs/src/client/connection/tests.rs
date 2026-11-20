use super::*;
use std::time::Duration;
use tokio::io::duplex;

fn rect_header(rect: Rect, encoding: u32) -> Vec<u8> {
    let mut bytes = vec![0, 0, 0, 1];
    for value in [rect.x, rect.y, rect.width, rect.height] {
        bytes.extend(value.to_be_bytes());
    }
    bytes.extend(encoding.to_be_bytes());
    bytes
}

#[tokio::test]
async fn oversized_initialization_is_rejected_before_payload_reads() {
    for (width, height, length) in [
        (u16::MAX, 1, 0),
        (8192, 8192, 0),
        (0, 1, 0),
        (10, 10, u32::MAX),
    ] {
        let (mut client, mut server) = duplex(256);
        server.write_u16(width).await.unwrap();
        server.write_u16(height).await.unwrap();
        server
            .write_all(&Vec::<u8>::from(PixelFormat::rgba()))
            .await
            .unwrap();
        server.write_u32(length).await.unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            read_server_init(&mut client, &mut Some(PixelFormat::rgba()), &|_| async {
                Ok(())
            }),
        )
        .await
        .unwrap();
        assert!(result.is_err());
    }
}

#[tokio::test]
async fn invalid_rectangles_and_lengths_are_rejected_before_payload_reads() {
    let rect = Rect {
        x: 0,
        y: 0,
        width: 1,
        height: 1,
    };
    let mut copy = rect_header(rect, VncEncoding::CopyRect.into());
    copy.extend([0, 64, 0, 0]);
    let mut zrle = rect_header(rect, VncEncoding::Zrle.into());
    zrle.extend(u32::MAX.to_be_bytes());
    let mut clipboard = vec![3, 0, 0, 0];
    clipboard.extend(u32::MAX.to_be_bytes());
    for payload in [
        rect_header(rect, 12345),
        rect_header(rect, VncEncoding::Tight.into()), // not negotiated
        rect_header(Rect { x: 64, ..rect }, 0),
        rect_header(
            Rect {
                x: u16::MAX,
                ..rect
            },
            0,
        ),
        rect_header(
            Rect {
                width: u16::MAX,
                ..rect
            },
            VncEncoding::DesktopSizePseudo.into(),
        ),
        copy,
        zrle,
        clipboard,
        vec![1],
    ] {
        let (mut client, mut server) = duplex(256);
        server.write_all(&payload).await.unwrap();
        let (_stop, mut stopped) = oneshot::channel();
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            asycn_vnc_read_loop(
                &mut client,
                &PixelFormat::rgba(),
                &|_| async { Ok(()) },
                &mut stopped,
                &[
                    VncEncoding::Raw,
                    VncEncoding::CopyRect,
                    VncEncoding::Zrle,
                    VncEncoding::DesktopSizePseudo,
                ],
                &AtomicU32::new(pack_screen((64, 64))),
                &DesktopState::default(),
            ),
        )
        .await
        .unwrap();
        assert!(result.is_err());
    }
}

#[tokio::test]
async fn raw_is_implicit_and_resize_changes_decoder_bounds() {
    let mut bytes = rect_header(
        Rect {
            x: 0,
            y: 0,
            width: 128,
            height: 96,
        },
        VncEncoding::DesktopSizePseudo.into(),
    );
    bytes.extend(rect_header(
        Rect {
            x: 127,
            y: 95,
            width: 1,
            height: 1,
        },
        0,
    ));
    bytes.extend([1, 2, 3, 255]);
    let output = std::sync::Mutex::new(Vec::new());
    let (_stop, mut stopped) = oneshot::channel();
    let result = asycn_vnc_read_loop(
        &mut bytes.as_slice(),
        &PixelFormat::rgba(),
        &|event| {
            output.lock().unwrap().push(event);
            async { Ok(()) }
        },
        &mut stopped,
        &[VncEncoding::DesktopSizePseudo],
        &AtomicU32::new(pack_screen((64, 64))),
        &DesktopState::default(),
    )
    .await;
    assert!(matches!(result, Err(VncError::IoError(_))));
    let output = output.into_inner().unwrap();
    assert!(
        matches!(&output[0], VncEvent::SetResolution(size) if (size.width, size.height) == (128, 96))
    );
    assert!(
        matches!(&output[1], VncEvent::RawImage(rect, bytes) if (rect.x, rect.y) == (127, 95) && bytes == &[1, 2, 3, 255])
    );
}

#[tokio::test]
async fn shutdown_interrupts_a_full_event_queue() {
    let (events, mut received) = channel(OUTPUT_CHANNEL_SIZE);
    for _ in 0..OUTPUT_CHANNEL_SIZE {
        events.try_send(VncEvent::Bell).unwrap();
    }
    let calls = std::cell::Cell::new(0);
    let output = |event| {
        calls.set(calls.get() + 1);
        events.send(event)
    };
    let (stop, mut stopped) = oneshot::channel();
    let mut input = &[2_u8][..];
    let format = PixelFormat::rgba();
    let deliver = |event| {
        let send = output(event);
        async {
            send.await?;
            Ok(())
        }
    };
    let screen = AtomicU32::new(pack_screen((1, 1)));
    let desktop = DesktopState::default();
    let task = asycn_vnc_read_loop(
        &mut input,
        &format,
        &deliver,
        &mut stopped,
        &[],
        &screen,
        &desktop,
    );
    tokio::pin!(task);
    assert!(futures::poll!(task.as_mut()).is_pending());
    assert_eq!(calls.get(), 1);
    assert_eq!(events.capacity(), 0);
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
    for _ in 0..OUTPUT_CHANNEL_SIZE {
        assert!(matches!(received.try_recv(), Ok(VncEvent::Bell)));
    }
    assert!(received.try_recv().is_err());
}

#[tokio::test]
async fn full_bridge_resumes_without_unrelated_input_and_cancels_promptly() {
    for cancel in [false, true] {
        let (client, mut server) = duplex(1);
        let (_input, input) = channel(INPUT_CHANNEL_SIZE);
        let (bridge, mut packets) = channel(2);
        for _ in 0..2 {
            bridge.try_send(Ok(vec![0])).unwrap();
        }
        let (stop, stopped) = oneshot::channel();
        server.write_all(&[7]).await.unwrap();
        let task = async_connection_process_loop(client, input, bridge, stopped);
        tokio::pin!(task);
        assert!(futures::poll!(task.as_mut()).is_pending());
        // The network byte was consumed while every bridge slot remains occupied.
        assert_eq!(packets.len(), 2);
        assert!(futures::poll!(Box::pin(server.write_all(&[8]))).is_ready());
        if !cancel {
            assert_eq!(packets.recv().await.unwrap().unwrap(), [0]);
            assert!(futures::poll!(task.as_mut()).is_pending());
            assert_eq!(packets.recv().await.unwrap().unwrap(), [0]);
            assert_eq!(packets.recv().await.unwrap().unwrap(), [7]);
        }
        stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        let mut byte = [0];
        assert_eq!(server.read(&mut byte).await.unwrap(), 0);
    }
}

#[tokio::test]
async fn shutdown_interrupts_a_blocked_socket_write() {
    let (client, mut server) = duplex(1);
    let (input, input_rx) = channel(INPUT_CHANNEL_SIZE);
    let (bridge, _packets) = channel(NETWORK_CHANNEL_SIZE);
    let (stop, stopped) = oneshot::channel();
    input
        .send(ClientMsg::ClientCutText("test".into()))
        .await
        .unwrap();
    let task = async_connection_process_loop(client, input_rx, bridge, stopped);
    tokio::pin!(task);
    assert!(futures::poll!(task.as_mut()).is_pending());
    assert_eq!(input.capacity(), INPUT_CHANNEL_SIZE);
    assert_eq!(server.read_u8().await.unwrap(), 6); // first byte of ClientCutText
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(server.read(&mut [0]).await.unwrap(), 0);
}

#[tokio::test]
async fn decoder_exit_releases_an_idle_socket() {
    let (client, mut server) = duplex(1);
    let (_input, input) = channel(INPUT_CHANNEL_SIZE);
    let (bridge, packets) = channel(NETWORK_CHANNEL_SIZE);
    let (_stop, stopped) = oneshot::channel();
    let task = async_connection_process_loop(client, input, bridge, stopped);
    tokio::pin!(task);
    assert!(futures::poll!(task.as_mut()).is_pending());
    drop(packets);
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(server.read(&mut [0]).await.unwrap(), 0);
}

#[tokio::test]
async fn full_input_queue_does_not_hold_the_client_lock_during_close() {
    let (input_ch, mut input) = channel(INPUT_CHANNEL_SIZE);
    for _ in 0..INPUT_CHANNEL_SIZE {
        input_ch
            .try_send(ClientMsg::ClientCutText(String::new()))
            .unwrap();
    }
    let (_events, output_ch) = channel(OUTPUT_CHANNEL_SIZE);
    let (network_stop, network_stopped) = oneshot::channel();
    let (decoder_stop, decoder_stopped) = oneshot::channel();
    let desktop = Arc::new(DesktopState::default());
    let client = VncClient {
        server_name: Arc::from(""),
        desktop: Arc::clone(&desktop),
        input_ch: input_ch.clone(),
        inner: Arc::new(Mutex::new(VncInner {
            name: String::new(),
            screen: Arc::new(AtomicU32::new(pack_screen((1, 1)))),
            desktop,
            input_ch,
            output_ch,
            decoding_stop: Some(decoder_stop),
            net_conn_stop: Some(network_stop),
            closed: false,
        })),
    };
    let pending = client.input(X11Event::Refresh);
    tokio::pin!(pending);
    assert!(futures::poll!(pending.as_mut()).is_pending());
    tokio::time::timeout(Duration::from_secs(1), client.close())
        .await
        .unwrap()
        .unwrap();
    network_stopped.await.unwrap();
    decoder_stopped.await.unwrap();
    // Even if capacity becomes available during close, no stale input is queued.
    input.recv().await.unwrap();
    assert!(matches!(pending.await, Err(VncError::ClientNotRunning)));
    assert_eq!(input.len(), INPUT_CHANNEL_SIZE - 1);
}

#[tokio::test]
async fn server_name_survives_close_and_clone() {
    for name in ["", "Test workstation ÆØÅ"] {
        let (client_stream, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            super::resize_tests::handshake_named(&mut server, (2, 2), name).await;
            server
        });
        let client = super::resize_tests::connect(client_stream).await;
        let _server = server_task.await.unwrap();
        assert_eq!(client.server_name(), name);
        let clone = client.clone();
        client.close().await.unwrap();
        assert_eq!(clone.server_name(), name);
    }
}
