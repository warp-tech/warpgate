use super::resize_tests::{event, extended, handshake, rect_header, single};
use super::*;
use crate::VncConnector;
use flate2::{write::ZlibEncoder, Compression};
use std::io::Write;
use tokio::io::duplex;

fn pixels(encoding: VncEncoding, x: u16, y: u16, compressor: &mut ZlibEncoder<Vec<u8>>) -> Vec<u8> {
    let mut packet = rect_header(
        Rect {
            x,
            y,
            width: 1,
            height: 1,
        },
        encoding.into(),
    );
    match encoding {
        VncEncoding::Raw => packet.extend([10, 20, 30, 255]),
        VncEncoding::Zrle => {
            // One solid-colour ZRLE tile, using the negotiated 24-bit CPIXEL.
            let start = compressor.get_ref().len();
            compressor.write_all(&[1, 10, 20, 30]).unwrap();
            compressor.flush().unwrap();
            let compressed = &compressor.get_ref()[start..];
            packet.extend((compressed.len() as u32).to_be_bytes());
            packet.extend(compressed);
        }
        _ => unreachable!(),
    }
    packet
}

#[tokio::test]
async fn server_layout_before_raw_or_zrle_pixels_applies_new_bounds_in_wire_order() {
    for encoding in [VncEncoding::Raw, VncEncoding::Zrle] {
        let (stream, mut server) = duplex(4096);
        let task = tokio::spawn(async move {
            handshake(&mut server, (80, 60)).await;
            let mut compressor = ZlibEncoder::new(Vec::new(), Compression::default());
            for (width, height) in [(80, 60), (160, 100), (40, 30)] {
                let mut packet = vec![0, 0, 0, 2];
                packet.extend(&single(0, 0, width, height)[4..]);
                packet.extend(&pixels(encoding, width - 1, height - 1, &mut compressor)[4..]);
                server.write_all(&packet).await.unwrap();
            }
            server.write_all(&[2]).await.unwrap(); // Bell proves the decoder stayed aligned.
            let mut byte = [0];
            assert_eq!(server.read(&mut byte).await.unwrap(), 0);
        });
        let client = VncConnector::new(stream)
            .set_auth_method(async { Ok(String::new()) })
            .set_pixel_format(PixelFormat::rgba())
            .add_encoding(encoding)
            .add_encoding(VncEncoding::ExtendedDesktopSizePseudo)
            .allow_shared(true)
            .build()
            .unwrap()
            .try_start()
            .await
            .unwrap()
            .finish()
            .unwrap();
        assert!(matches!(event(&client).await, VncEvent::SetResolution(_)));
        for (width, height) in [(80, 60), (160, 100), (40, 30)] {
            assert!(
                matches!(event(&client).await, VncEvent::DesktopUpdate(update)
                if update.layout.as_ref().is_some_and(|layout| (layout.width, layout.height) == (width, height)))
            );
            assert!(
                matches!(event(&client).await, VncEvent::RawImage(rect, bytes)
                if (rect.x, rect.y) == (width - 1, height - 1) && bytes == [10, 20, 30, 255])
            );
        }
        assert!(matches!(event(&client).await, VncEvent::Bell));
        assert_eq!(client.desktop_layout().unwrap().width, 40);
        client.close().await.unwrap();
        task.await.unwrap();
    }
}

#[tokio::test]
async fn server_layout_does_not_allow_pixels_outside_the_new_desktop() {
    let (stream, mut server) = duplex(4096);
    let task = tokio::spawn(async move {
        handshake(&mut server, (80, 60)).await;
        let mut packet = vec![0, 0, 0, 2];
        packet.extend(&single(0, 0, 40, 30)[4..]);
        packet.extend(
            &pixels(
                VncEncoding::Raw,
                79,
                59,
                &mut ZlibEncoder::new(Vec::new(), Compression::default()),
            )[4..],
        );
        server.write_all(&packet).await.unwrap();
        let mut byte = [0];
        let _ = server.read(&mut byte).await;
    });
    let client = extended(stream).await;
    event(&client).await;
    assert!(matches!(event(&client).await, VncEvent::DesktopUpdate(_)));
    assert!(matches!(event(&client).await, VncEvent::Error(_)));
    client.close().await.unwrap();
    task.await.unwrap();
}
