use super::*;
use std::sync::Mutex;

fn compress(compressor: &mut flate2::Compress, data: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(1024);
    compressor
        .compress_vec(data, &mut output, flate2::FlushCompress::Sync)
        .unwrap();
    let mut packet = (output.len() as u32).to_be_bytes().to_vec();
    packet.extend(output);
    packet
}

#[tokio::test]
async fn malformed_palette_index_and_runs_return_errors() {
    // 1x1 tiles: packed index 3 into a three-color palette; overlong plain/indexed
    // runs; index 2 into a two-color palette; illegal subencoding; truncated pixel.
    for data in [
        vec![3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xc0],
        vec![128, 1, 2, 3, 1],
        vec![130, 1, 2, 3, 4, 5, 6, 128, 1],
        vec![130, 1, 2, 3, 4, 5, 6, 2],
        vec![129, 1, 2, 3],
        vec![0, 1],
    ] {
        let mut compressor = flate2::Compress::new(flate2::Compression::fast(), true);
        let packet = compress(&mut compressor, &data);
        let mut input = packet.as_slice();
        let result = Decoder::new()
            .decode(
                &PixelFormat::rgba(),
                &Rect {
                    x: 0,
                    y: 0,
                    width: 1,
                    height: 1,
                },
                &mut input,
                &|_| async { Ok(()) },
            )
            .await;
        assert!(result.is_err(), "malformed input accepted: {data:?}");
    }
}

#[tokio::test]
async fn valid_modes_and_persistent_compression_preserve_pixels() {
    let mut compressor = flate2::Compress::new(flate2::Compression::fast(), true);
    let mut decoder = Decoder::new();
    // Raw, solid, packed-palette, plain RLE and palette RLE for a two-pixel tile.
    for (data, expected) in [
        (vec![0, 1, 2, 3, 4, 5, 6], vec![1, 2, 3, 255, 4, 5, 6, 255]),
        (vec![1, 1, 2, 3], vec![1, 2, 3, 255, 1, 2, 3, 255]),
        (
            vec![2, 1, 2, 3, 4, 5, 6, 0x40],
            vec![1, 2, 3, 255, 4, 5, 6, 255],
        ),
        (vec![128, 1, 2, 3, 1], vec![1, 2, 3, 255, 1, 2, 3, 255]),
        (
            vec![130, 1, 2, 3, 4, 5, 6, 128, 1],
            vec![1, 2, 3, 255, 1, 2, 3, 255],
        ),
    ] {
        let packet = compress(&mut compressor, &data);
        let mut input = packet.as_slice();
        let output = Mutex::new(Vec::new());
        decoder
            .decode(
                &PixelFormat::rgba(),
                &Rect {
                    x: 0,
                    y: 0,
                    width: 2,
                    height: 1,
                },
                &mut input,
                &|event| {
                    output.lock().unwrap().push(event);
                    async { Ok(()) }
                },
            )
            .await
            .unwrap();
        let VncEvent::RawImage(_, pixels) = output.into_inner().unwrap().remove(0) else {
            panic!("expected pixels");
        };
        assert_eq!(pixels, expected);
    }
}
