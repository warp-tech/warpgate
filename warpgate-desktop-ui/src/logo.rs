use std::io::Cursor;
use std::sync::OnceLock;

use embedded_graphics::image::ImageRaw;
use embedded_graphics::pixelcolor::Rgb888;

pub fn logo() -> &'static ImageRaw<'static, Rgb888> {
    static PIXELS: OnceLock<(Vec<u8>, u32)> = OnceLock::new();
    static IMAGE: OnceLock<ImageRaw<'static, Rgb888>> = OnceLock::new();

    IMAGE.get_or_init(|| {
        let (rgb, width) = PIXELS.get_or_init(decode_logo);
        ImageRaw::new(rgb, *width)
    })
}

#[allow(clippy::expect_used)]
#[allow(clippy::panic)]
fn decode_logo() -> (Vec<u8>, u32) {
    static PNG: &[u8] = include_bytes!("../assets/logo.png");
    let mut reader = png::Decoder::new(Cursor::new(&PNG))
        .read_info()
        .expect("logo unreadable");

    #[allow(clippy::expect_used)]
    let mut buf = vec![0u8; reader.output_buffer_size().expect("out of memory")];
    let info = reader.next_frame(&mut buf).expect("logo unreadable");
    assert!(info.bit_depth == png::BitDepth::Eight, "logo has unexpected bit depth: {:?}", info.bit_depth);
    buf.truncate(info.buffer_size());

    let rgb = match info.color_type {
        png::ColorType::Rgb => buf,
        // The logo is actually fully opaque
        png::ColorType::Rgba => buf
            .chunks_exact(4)
            .flat_map(|px| px.iter().copied().take(3))
            .collect(),
        t => panic!("logo has unexpected color type: {t:?}"),
    };

    (rgb, info.width)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn logo_decodes() {
        decode_logo();
    }
}
