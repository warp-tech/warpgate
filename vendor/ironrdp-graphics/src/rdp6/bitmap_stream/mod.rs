mod decoder;
mod encoder;

pub use decoder::*;
pub use encoder::*;

#[cfg(test)]
mod tests {
    use super::*;

    fn buffer_from_bmp(bmp_image: &[u8], width: usize, height: usize) -> Vec<u8> {
        let expected_bmp = bmp::from_reader(&mut std::io::Cursor::new(bmp_image)).unwrap();

        let mut expected_buffer = vec![0; width * height * 3];
        for (idx, (x, y)) in expected_bmp.coordinates().enumerate() {
            let pixel = expected_bmp.get_pixel(x, y);

            let offset = idx * 3;
            expected_buffer[offset] = pixel.r;
            expected_buffer[offset + 1] = pixel.g;
            expected_buffer[offset + 2] = pixel.b;
        }

        expected_buffer
    }

    fn assert_decoded_image(pdu: &[u8], expected_bmp: &[u8], width: usize, height: usize) {
        let expected_buffer = buffer_from_bmp(expected_bmp, width, height);

        let mut actual = Vec::new();
        BitmapStreamDecoder::default()
            .decode_bitmap_stream_to_rgb24(pdu, &mut actual, width, height)
            .unwrap();

        assert_eq!(actual.as_slice(), expected_buffer.as_slice());
    }

    #[test]
    fn decode_32x64_rgb_raw() {
        // RGB (No alpha), no RLE
        assert_decoded_image(
            include_bytes!("../test_assets/32x64_rgb_raw.bin"),
            include_bytes!("../test_assets/32x64_rgb_raw.bmp"),
            32,
            64,
        );
    }

    #[test]
    fn decode_64x24_argb_rle() {
        // ARGB (With alpha), RLE
        assert_decoded_image(
            include_bytes!("../test_assets/64x24_argb_rle.bin"),
            include_bytes!("../test_assets/64x24_argb_rle.bmp"),
            64,
            24,
        );
    }

    #[test]
    fn decode_64x64_aycocg_rle() {
        // AYCoCg (With alpha), RLE, no chroma subsampling
        assert_decoded_image(
            include_bytes!("../test_assets/64x64_aycocg_rle.bin"),
            include_bytes!("../test_assets/64x64_aycocg_rle.bmp"),
            64,
            64,
        );
    }

    #[test]
    fn decode_64x64_ycocg_rle_ss() {
        // AYCoCg (No alpha), RLE, with chroma subsampling
        assert_decoded_image(
            include_bytes!("../test_assets/64x64_ycocg_rle_ss.bin"),
            include_bytes!("../test_assets/64x64_ycocg_rle_ss.bmp"),
            64,
            64,
        );
    }

    #[test]
    fn decode_64x35_ycocg_rle_ss() {
        // AYCoCg (No alpha), RLE, with chroma subsampling + odd resolution
        assert_decoded_image(
            include_bytes!("../test_assets/64x35_ycocg_rle_ss.bin"),
            include_bytes!("../test_assets/64x35_ycocg_rle_ss.bmp"),
            64,
            35,
        );
    }

    #[test]
    fn decode_64x64_ycocg_raw_ss() {
        // AYCoCg (No alpha), no RLE, with chroma subsampling
        assert_decoded_image(
            include_bytes!("../test_assets/64x64_ycocg_raw_ss.bin"),
            include_bytes!("../test_assets/64x64_ycocg_raw_ss.bmp"),
            64,
            64,
        );
    }

    fn assert_encoded_image(expected_pdu: &[u8], bmp: &[u8], width: usize, height: usize, rle: bool) {
        let image = buffer_from_bmp(bmp, width, height);

        let mut pdu = vec![0; width * height * 4 + 2];
        let written = BitmapStreamEncoder::new(width, height)
            .encode_bitmap::<RgbChannels>(&image, &mut pdu, rle)
            .unwrap();

        // last byte is padding when !rle
        assert_eq!(&pdu[0..written - 1], &expected_pdu[0..written - 1]);
    }

    fn encode_decode_test(bmp: &[u8], width: usize, height: usize, rle: bool) {
        let image = buffer_from_bmp(bmp, width, height);

        let mut pdu = vec![0; width * height * 4 + 2];
        let written = BitmapStreamEncoder::new(width, height)
            .encode_bitmap::<RgbChannels>(&image, &mut pdu, rle)
            .unwrap();

        let mut actual = Vec::new();
        BitmapStreamDecoder::default()
            .decode_bitmap_stream_to_rgb24(&pdu[..written], &mut actual, width, height)
            .unwrap();

        assert_eq!(&image.as_slice(), &actual.as_slice());
    }

    #[test]
    fn encode_32x64_rgb_raw() {
        // RGB (No alpha), no RLE
        assert_encoded_image(
            include_bytes!("../test_assets/32x64_rgb_raw.bin"),
            include_bytes!("../test_assets/32x64_rgb_raw.bmp"),
            32,
            64,
            false,
        );
    }

    #[test]
    fn encode_decode_32x64_rgb_raw() {
        // RGB (No alpha), no RLE
        encode_decode_test(include_bytes!("../test_assets/32x64_rgb_raw.bmp"), 32, 64, false);
    }

    #[test]
    fn encode_decode_32x64_rgb_rle() {
        // RGB (No alpha), with RLE
        encode_decode_test(include_bytes!("../test_assets/32x64_rgb_raw.bmp"), 32, 64, true);
    }

    #[test]
    fn encode_decode_64x24_rgb_raw() {
        // RGB (No alpha), no RLE
        encode_decode_test(include_bytes!("../test_assets/64x24_argb_rle.bmp"), 32, 64, false);
    }

    #[test]
    fn encode_decode_64x24_rgb_rle() {
        // RGB (No alpha), with RLE
        encode_decode_test(include_bytes!("../test_assets/64x24_argb_rle.bmp"), 32, 64, true);
    }

    #[test]
    fn encode_decode_64x64_rgb_raw() {
        // RGB (No alpha), no RLE
        encode_decode_test(include_bytes!("../test_assets/64x64_aycocg_rle.bmp"), 64, 64, false);
    }

    #[test]
    fn encode_decode_64x64_rgb_rle() {
        // RGB (No alpha), with RLE
        encode_decode_test(include_bytes!("../test_assets/64x64_aycocg_rle.bmp"), 64, 64, true);
    }
}
