use super::*;
use crate::{PixelFormat, Rect, VncError, VncEvent};
use std::sync::Mutex;

#[tokio::test]
async fn tight_fill_copy_and_palette_modes_preserve_pixels() {
    let rect = Rect {
        x: 0,
        y: 0,
        width: 2,
        height: 1,
    };
    for (bytes, expected) in [
        (vec![0x80, 1, 2, 3], vec![1, 2, 3, 255, 1, 2, 3, 255]),
        (vec![0, 1, 2, 3, 4, 5, 6], vec![1, 2, 3, 255, 4, 5, 6, 255]),
        (
            vec![0x40, 1, 1, 1, 2, 3, 4, 5, 6, 0x40],
            vec![1, 2, 3, 255, 4, 5, 6, 255],
        ),
        (
            vec![0x40, 1, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 2],
            vec![1, 2, 3, 255, 7, 8, 9, 255],
        ),
    ] {
        let output = Mutex::new(Vec::new());
        TightDecoder::new()
            .decode(
                &PixelFormat::rgba(),
                &rect,
                &mut bytes.as_slice(),
                &|event| {
                    output.lock().unwrap().push(event);
                    async { Ok(()) }
                },
            )
            .await
            .unwrap();
        assert!(
            matches!(&output.into_inner().unwrap()[0], VncEvent::RawImage(_, pixels) if pixels == &expected)
        );
    }
}

#[tokio::test]
async fn tight_rejects_invalid_palette_indexes_and_unsupported_formats() {
    let rect = Rect {
        x: 0,
        y: 0,
        width: 2,
        height: 1,
    };
    for bytes in [
        vec![0x40, 1, 0], // a single color must use Fill
        vec![0x40, 1, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 3, 0],
    ] {
        let result = TightDecoder::new()
            .decode(
                &PixelFormat::rgba(),
                &rect,
                &mut bytes.as_slice(),
                &|_| async { Ok(()) },
            )
            .await;
        assert!(matches!(result, Err(VncError::InvalidImageData)));
    }
    let mut format = PixelFormat::rgba();
    format.true_color_flag = 0;
    format.red_shift = 255; // ignored for indexed color, must never be shifted
    let result = TightDecoder::new()
        .decode(&format, &rect, &mut &[][..], &|_| async { Ok(()) })
        .await;
    assert!(matches!(result, Err(VncError::WrongPixelFormat)));
}

#[tokio::test]
async fn cursor_preserves_alpha_mask_and_accepts_empty_shapes() {
    for (width, bytes, expected) in [
        (1, vec![1, 2, 3, 0, 0x80], vec![1, 2, 3, 255]),
        (1, vec![1, 2, 3, 255, 0], vec![1, 2, 3, 0]),
        (0, vec![], vec![]),
    ] {
        let output = Mutex::new(Vec::new());
        CursorDecoder::new()
            .decode(
                &PixelFormat::rgba(),
                &Rect {
                    x: 0,
                    y: 0,
                    width,
                    height: 1,
                },
                &mut bytes.as_slice(),
                &|event| {
                    output.lock().unwrap().push(event);
                    async { Ok(()) }
                },
            )
            .await
            .unwrap();
        assert!(
            matches!(&output.into_inner().unwrap()[0], VncEvent::SetCursor(_, pixels) if pixels == &expected)
        );
    }
}

#[tokio::test]
async fn tight_rejects_component_widths_its_filters_cannot_decode() {
    let mut format = PixelFormat::rgba();
    format.red_max = 65535;
    format.red_shift = 0;
    format.green_max = 127;
    format.green_shift = 16;
    format.blue_max = 1;
    format.blue_shift = 23;
    assert!(format.validate().is_ok());
    let result = TightDecoder::new()
        .decode(
            &format,
            &Rect {
                x: 0,
                y: 0,
                width: 1,
                height: 1,
            },
            &mut &[0x40, 2, 255, 255, 255][..],
            &|_| async { Ok(()) },
        )
        .await;
    assert!(matches!(result, Err(VncError::WrongPixelFormat)));
}
