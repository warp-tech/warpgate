//! Interleaved Run-Length Encoding (RLE) Bitmap Codec
//!
//! # References
//!
//! - Microsoft Learn:
//!   - [RLE_BITMAP_STREAM](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b3b60873-16a8-4cbc-8aaa-5f0a93083280)
//!   - [Pseudo-code](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b6a3f5c2-0804-4c10-9d25-a321720fd23e)
//!
//! - FreeRDP:
//!   - [interleaved.c](https://github.com/FreeRDP/FreeRDP/blob/db98f16e5bce003c898e8c85eb7af964f22a16a8/libfreerdp/codec/interleaved.c#L3)
//!   - [bitmap.c](https://github.com/FreeRDP/FreeRDP/blob/3a8dce07ea0262b240025bd68b63801578ca63f0/libfreerdp/codec/include/bitmap.c)
use core::fmt;
use core::ops::BitXor;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RlePixelFormat {
    Rgb24,
    Rgb16,
    Rgb15,
    Rgb8,
}

/// Decompresses an RLE compressed bitmap.
///
/// `src`: source buffer containing compressed bitmap
/// `dst`: destination buffer
/// `width`: decompressed bitmap width
/// `height`: decompressed bitmap height
/// `bpp`: bits per pixel
pub fn decompress(
    src: &[u8],
    dst: &mut Vec<u8>,
    width: usize,
    height: usize,
    bpp: usize,
) -> Result<RlePixelFormat, RleError> {
    match bpp {
        Mode24Bpp::BPP => decompress_24_bpp(src, dst, width, height),
        Mode16Bpp::BPP => decompress_16_bpp(src, dst, width, height),
        Mode15Bpp::BPP => decompress_15_bpp(src, dst, width, height),
        Mode8Bpp::BPP => decompress_8_bpp(src, dst, width, height),
        invalid => Err(RleError::InvalidBpp { bpp: invalid }),
    }
}

/// Decompresses a 24-bpp RLE compressed bitmap.
///
/// `src`: source buffer containing compressed bitmap
/// `dst`: destination buffer
/// `width`: decompressed bitmap width
/// `height`: decompressed bitmap height
pub fn decompress_24_bpp(
    src: &[u8],
    dst: &mut Vec<u8>,
    width: usize,
    height: usize,
) -> Result<RlePixelFormat, RleError> {
    decompress_helper::<Mode24Bpp>(src, dst, width, height)
}

/// Decompresses a 16-bpp RLE compressed bitmap.
///
/// `src`: source buffer containing compressed bitmap
/// `dst`: destination buffer
/// `width`: decompressed bitmap width
/// `height`: decompressed bitmap height
pub fn decompress_16_bpp(
    src: &[u8],
    dst: &mut Vec<u8>,
    width: usize,
    height: usize,
) -> Result<RlePixelFormat, RleError> {
    decompress_helper::<Mode16Bpp>(src, dst, width, height)
}

/// Decompresses a 15-bpp RLE compressed bitmap.
///
/// `src`: source buffer containing compressed bitmap
/// `dst`: destination buffer
/// `width`: decompressed bitmap width
/// `height`: decompressed bitmap height
pub fn decompress_15_bpp(
    src: &[u8],
    dst: &mut Vec<u8>,
    width: usize,
    height: usize,
) -> Result<RlePixelFormat, RleError> {
    decompress_helper::<Mode15Bpp>(src, dst, width, height)
}

/// Decompresses a 8-bpp RLE compressed bitmap.
///
/// `src`: source buffer containing compressed bitmap
/// `dst`: destination buffer
/// `width`: decompressed bitmap width
/// `height`: decompressed bitmap height
pub fn decompress_8_bpp(
    src: &[u8],
    dst: &mut Vec<u8>,
    width: usize,
    height: usize,
) -> Result<RlePixelFormat, RleError> {
    decompress_helper::<Mode8Bpp>(src, dst, width, height)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RleError {
    InvalidBpp {
        bpp: usize,
    },
    BadOrderCode,
    NotEnoughBytes {
        expected: usize,
        actual: usize,
    },
    InvalidImageSize {
        maximum_additional: usize,
        required_additional: usize,
    },
    EmptyImage,
    UnexpectedZeroLength,
}

impl fmt::Display for RleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RleError::InvalidBpp { bpp } => write!(f, "invalid bytes per pixel: {bpp}"),
            RleError::BadOrderCode => write!(f, "bad RLE order code"),
            RleError::NotEnoughBytes { expected, actual } => {
                write!(f, "not enough bytes: expected {expected} bytes, but got {actual}")
            }
            RleError::InvalidImageSize {
                maximum_additional,
                required_additional,
            } => {
                write!(
                    f,
                    "invalid image size advertised: output buffer can only receive at most {maximum_additional} additional bytes, but {required_additional} bytes are required"
                )
            }
            RleError::EmptyImage => write!(f, "height or width is zero"),
            RleError::UnexpectedZeroLength => write!(f, "unexpected zero-length"),
        }
    }
}

fn decompress_helper<Mode: DepthMode>(
    src: &[u8],
    dst: &mut Vec<u8>,
    width: usize,
    height: usize,
) -> Result<RlePixelFormat, RleError> {
    if width == 0 || height == 0 {
        return Err(RleError::EmptyImage);
    }

    let row_delta = Mode::COLOR_DEPTH * width;
    dst.resize(row_delta * height, 0);
    decompress_impl::<Mode>(src, dst, row_delta)?;

    Ok(Mode::PIXEL_FORMAT)
}

macro_rules! ensure_size {
    (from: $buf:ident, size: $expected:expr) => {{
        let actual = $buf.remaining_len();
        let expected = $expected;
        if expected > actual {
            return Err(RleError::NotEnoughBytes { expected, actual });
        }
    }};
    (into: $buf:ident, size: $required_additional:expr) => {{
        let maximum_additional = $buf.remaining_len();
        let required_additional = $required_additional;
        if required_additional > maximum_additional {
            return Err(RleError::InvalidImageSize {
                maximum_additional,
                required_additional,
            });
        }
    }};
}

/// RLE decompression implementation
///
/// `src`: source buffer containing compressed bitmap
/// `dst`: destination buffer
/// `row_delta`: scanline length in bytes
fn decompress_impl<Mode: DepthMode>(src: &[u8], dst: &mut [u8], row_delta: usize) -> Result<(), RleError> {
    let mut src = Buf::new(src);
    let mut dst = BufMut::new(dst);

    let mut fg_pel = Mode::WHITE_PIXEL;
    let mut insert_fg_pel = false;
    let mut is_first_line = true;

    while !src.eof() {
        // Watch out for the end of the first scanline.
        if is_first_line && dst.pos >= row_delta {
            is_first_line = false;
            insert_fg_pel = false;
        }

        ensure_size!(from: src, size: 1);

        let header = src.read_u8();

        // Extract the compression order code ID from the compression order header.
        let code = Code::decode(header);

        // Extract run length
        let run_length = code.extract_run_length(header, &mut src)?;

        // Handle Background Run Orders.
        if code == Code::REGULAR_BG_RUN || code == Code::MEGA_MEGA_BG_RUN {
            ensure_size!(into: dst, size: run_length * Mode::COLOR_DEPTH);

            if is_first_line {
                let num_iterations = if insert_fg_pel {
                    Mode::write_pixel(&mut dst, fg_pel);
                    run_length - 1
                } else {
                    run_length
                };

                for _ in 0..num_iterations {
                    Mode::write_pixel(&mut dst, Mode::BLACK_PIXEL);
                }
            } else {
                let num_iterations = if insert_fg_pel {
                    let pixel_above = dst.read_pixel_above::<Mode>(row_delta);
                    let xored = pixel_above ^ fg_pel;
                    Mode::write_pixel(&mut dst, xored);
                    run_length - 1
                } else {
                    run_length
                };

                for _ in 0..num_iterations {
                    let pixel_above = dst.read_pixel_above::<Mode>(row_delta);
                    Mode::write_pixel(&mut dst, pixel_above);
                }
            }

            // A follow-on background run order will need a foreground pel inserted.
            insert_fg_pel = true;

            continue;
        }

        // For any of the other run-types a follow-on background run
        // order does not need a foreground pel inserted.
        insert_fg_pel = false;

        if code == Code::REGULAR_FG_RUN
            || code == Code::MEGA_MEGA_FG_RUN
            || code == Code::LITE_SET_FG_FG_RUN
            || code == Code::MEGA_MEGA_SET_FG_RUN
        {
            // Handle Foreground Run Orders.

            ensure_size!(from: src, size: Mode::COLOR_DEPTH);

            if code == Code::LITE_SET_FG_FG_RUN || code == Code::MEGA_MEGA_SET_FG_RUN {
                fg_pel = Mode::read_pixel(&mut src);
            }

            ensure_size!(into: dst, size: run_length * Mode::COLOR_DEPTH);

            if is_first_line {
                for _ in 0..run_length {
                    Mode::write_pixel(&mut dst, fg_pel);
                }
            } else {
                for _ in 0..run_length {
                    let pixel_above = dst.read_pixel_above::<Mode>(row_delta);
                    let xored = pixel_above ^ fg_pel;
                    Mode::write_pixel(&mut dst, xored);
                }
            }
        } else if code == Code::LITE_DITHERED_RUN || code == Code::MEGA_MEGA_DITHERED_RUN {
            // Handle Dithered Run Orders.

            ensure_size!(from: src, size: 2 * Mode::COLOR_DEPTH);

            let pixel_a = Mode::read_pixel(&mut src);
            let pixel_b = Mode::read_pixel(&mut src);

            ensure_size!(into: dst, size: run_length * 2 * Mode::COLOR_DEPTH);

            for _ in 0..run_length {
                Mode::write_pixel(&mut dst, pixel_a);
                Mode::write_pixel(&mut dst, pixel_b);
            }
        } else if code == Code::REGULAR_COLOR_RUN || code == Code::MEGA_MEGA_COLOR_RUN {
            // Handle Color Run Orders.

            ensure_size!(from: src, size: Mode::COLOR_DEPTH);

            let pixel = Mode::read_pixel(&mut src);

            ensure_size!(into: dst, size: run_length * Mode::COLOR_DEPTH);

            for _ in 0..run_length {
                Mode::write_pixel(&mut dst, pixel);
            }
        } else if code == Code::REGULAR_FGBG_IMAGE
            || code == Code::MEGA_MEGA_FGBG_IMAGE
            || code == Code::LITE_SET_FG_FGBG_IMAGE
            || code == Code::MEGA_MEGA_SET_FGBG_IMAGE
        {
            // Handle Foreground/Background Image Orders.

            if code == Code::LITE_SET_FG_FGBG_IMAGE || code == Code::MEGA_MEGA_SET_FGBG_IMAGE {
                ensure_size!(from: src, size: Mode::COLOR_DEPTH);
                fg_pel = Mode::read_pixel(&mut src);
            }

            let mut number_to_read = run_length;

            while number_to_read > 0 {
                let c_bits = core::cmp::min(8, number_to_read);

                ensure_size!(from: src, size: 1);
                let bitmask = src.read_u8();

                if is_first_line {
                    write_first_line_fg_bg_image::<Mode>(&mut dst, bitmask, fg_pel, c_bits)?;
                } else {
                    write_fg_bg_image::<Mode>(&mut dst, row_delta, bitmask, fg_pel, c_bits)?;
                }

                number_to_read -= c_bits;
            }
        } else if code == Code::REGULAR_COLOR_IMAGE || code == Code::MEGA_MEGA_COLOR_IMAGE {
            // Handle Color Image Orders.

            let byte_count = run_length * Mode::COLOR_DEPTH;

            ensure_size!(from: src, size: byte_count);
            ensure_size!(into: dst, size: byte_count);

            for _ in 0..byte_count {
                dst.write_u8(src.read_u8());
            }
        } else if code == Code::SPECIAL_FGBG_1 {
            // Handle Special Order 1.

            const MASK_SPECIAL_FG_BG_1: u8 = 0x03;

            if is_first_line {
                write_first_line_fg_bg_image::<Mode>(&mut dst, MASK_SPECIAL_FG_BG_1, fg_pel, 8)?;
            } else {
                write_fg_bg_image::<Mode>(&mut dst, row_delta, MASK_SPECIAL_FG_BG_1, fg_pel, 8)?;
            }
        } else if code == Code::SPECIAL_FGBG_2 {
            // Handle Special Order 2.

            const MASK_SPECIAL_FG_BG_2: u8 = 0x05;

            if is_first_line {
                write_first_line_fg_bg_image::<Mode>(&mut dst, MASK_SPECIAL_FG_BG_2, fg_pel, 8)?;
            } else {
                write_fg_bg_image::<Mode>(&mut dst, row_delta, MASK_SPECIAL_FG_BG_2, fg_pel, 8)?;
            }
        } else if code == Code::SPECIAL_WHITE {
            // Handle White Order.

            ensure_size!(into: dst, size: Mode::COLOR_DEPTH);

            Mode::write_pixel(&mut dst, Mode::WHITE_PIXEL);
        } else if code == Code::SPECIAL_BLACK {
            // Handle Black Order.

            ensure_size!(into: dst, size: Mode::COLOR_DEPTH);

            Mode::write_pixel(&mut dst, Mode::BLACK_PIXEL);
        } else {
            return Err(RleError::BadOrderCode);
        }
    }

    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Code(u8);

impl fmt::Debug for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::REGULAR_BG_RUN => "REGULAR_BG_RUN",
            Self::REGULAR_FG_RUN => "REGULAR_FG_RUN",
            Self::REGULAR_COLOR_RUN => "REGULAR_COLOR_RUN",
            Self::REGULAR_FGBG_IMAGE => "REGULAR_FGBG_IMAGE",
            Self::REGULAR_COLOR_IMAGE => "REGULAR_COLOR_IMAGE",

            Self::MEGA_MEGA_BG_RUN => "MEGA_MEGA_BG_RUN",
            Self::MEGA_MEGA_FG_RUN => "MEGA_MEGA_FG_RUN",
            Self::MEGA_MEGA_SET_FG_RUN => "MEGA_MEGA_SET_FG_RUN",
            Self::MEGA_MEGA_DITHERED_RUN => "MEGA_MEGA_DITHERED_RUN",
            Self::MEGA_MEGA_COLOR_RUN => "MEGA_MEGA_COLOR_RUN",
            Self::MEGA_MEGA_FGBG_IMAGE => "MEGA_MEGA_FGBG_IMAGE",
            Self::MEGA_MEGA_SET_FGBG_IMAGE => "MEGA_MEGA_SET_FGBG_IMAGE",
            Self::MEGA_MEGA_COLOR_IMAGE => "MEGA_MEGA_COLOR_IMAGE",

            Self::LITE_SET_FG_FG_RUN => "LITE_SET_FG_FG_RUN",
            Self::LITE_DITHERED_RUN => "LITE_DITHERED_RUN",
            Self::LITE_SET_FG_FGBG_IMAGE => "LITE_SET_FG_FGBG_IMAGE",

            Self::SPECIAL_FGBG_1 => "SPECIAL_FGBG_1",
            Self::SPECIAL_FGBG_2 => "SPECIAL_FGBG_2",
            Self::SPECIAL_WHITE => "SPECIAL_WHITE",
            Self::SPECIAL_BLACK => "SPECIAL_BLACK",

            _ => "UNKNOWN",
        };

        write!(f, "Code(0x{:02X}-{name})", self.0)
    }
}

impl Code {
    const REGULAR_BG_RUN: Code = Code(0x00);
    const REGULAR_FG_RUN: Code = Code(0x01);
    const REGULAR_COLOR_RUN: Code = Code(0x03);
    const REGULAR_FGBG_IMAGE: Code = Code(0x02);
    const REGULAR_COLOR_IMAGE: Code = Code(0x04);

    const MEGA_MEGA_BG_RUN: Code = Code(0xF0);
    const MEGA_MEGA_FG_RUN: Code = Code(0xF1);
    const MEGA_MEGA_SET_FG_RUN: Code = Code(0xF6);
    const MEGA_MEGA_DITHERED_RUN: Code = Code(0xF8);
    const MEGA_MEGA_COLOR_RUN: Code = Code(0xF3);
    const MEGA_MEGA_FGBG_IMAGE: Code = Code(0xF2);
    const MEGA_MEGA_SET_FGBG_IMAGE: Code = Code(0xF7);
    const MEGA_MEGA_COLOR_IMAGE: Code = Code(0xF4);

    const LITE_SET_FG_FG_RUN: Code = Code(0x0C);
    const LITE_DITHERED_RUN: Code = Code(0x0E);
    const LITE_SET_FG_FGBG_IMAGE: Code = Code(0x0D);

    const SPECIAL_FGBG_1: Code = Code(0xF9);
    const SPECIAL_FGBG_2: Code = Code(0xFA);
    const SPECIAL_WHITE: Code = Code(0xFD);
    const SPECIAL_BLACK: Code = Code(0xFE);

    fn decode(header: u8) -> Self {
        if (header & 0xC0) != 0xC0 {
            // REGULAR orders
            // (000x xxxx, 001x xxxx, 010x xxxx, 011x xxxx, 100x xxxx)
            Code(header >> 5)
        } else if (header & 0xF0) == 0xF0 {
            // MEGA and SPECIAL orders (0xF*)
            Code(header)
        } else {
            // LITE orders
            // (1100 xxxx, 1101 xxxx, 1110 xxxx)
            Code(header >> 4)
        }
    }

    /// Extract the run length of a compression order.
    fn extract_run_length(self, header: u8, src: &mut Buf<'_>) -> Result<usize, RleError> {
        match self {
            Self::REGULAR_FGBG_IMAGE => extract_run_length_fg_bg(header, MASK_REGULAR_RUN_LENGTH, src),

            Self::LITE_SET_FG_FGBG_IMAGE => extract_run_length_fg_bg(header, MASK_LITE_RUN_LENGTH, src),

            Self::REGULAR_BG_RUN | Self::REGULAR_FG_RUN | Self::REGULAR_COLOR_RUN | Self::REGULAR_COLOR_IMAGE => {
                extract_run_length_regular(header, src)
            }

            Self::LITE_SET_FG_FG_RUN | Self::LITE_DITHERED_RUN => extract_run_length_lite(header, src),

            Self::MEGA_MEGA_BG_RUN
            | Self::MEGA_MEGA_FG_RUN
            | Self::MEGA_MEGA_SET_FG_RUN
            | Self::MEGA_MEGA_DITHERED_RUN
            | Self::MEGA_MEGA_COLOR_RUN
            | Self::MEGA_MEGA_FGBG_IMAGE
            | Self::MEGA_MEGA_SET_FGBG_IMAGE
            | Self::MEGA_MEGA_COLOR_IMAGE => extract_run_length_mega_mega(src),

            Self::SPECIAL_FGBG_1 | Self::SPECIAL_FGBG_2 | Self::SPECIAL_WHITE | Self::SPECIAL_BLACK => Ok(0),

            _ => Ok(0),
        }
    }
}

const MASK_REGULAR_RUN_LENGTH: u8 = 0x1F;
const MASK_LITE_RUN_LENGTH: u8 = 0x0F;

/// Extract the run length of a Foreground/Background Image Order.
fn extract_run_length_fg_bg(header: u8, length_mask: u8, src: &mut Buf<'_>) -> Result<usize, RleError> {
    match header & length_mask {
        0 => {
            ensure_size!(from: src, size: 1);
            Ok(usize::from(src.read_u8()) + 1)
        }
        run_length => Ok(usize::from(run_length) * 8),
    }
}

/// Extract the run length of a regular-form compression order.
fn extract_run_length_regular(header: u8, src: &mut Buf<'_>) -> Result<usize, RleError> {
    match header & MASK_REGULAR_RUN_LENGTH {
        0 => {
            // An extended (MEGA) run.
            ensure_size!(from: src, size: 1);
            Ok(usize::from(src.read_u8()) + 32)
        }
        run_length => Ok(usize::from(run_length)),
    }
}

fn extract_run_length_lite(header: u8, src: &mut Buf<'_>) -> Result<usize, RleError> {
    match header & MASK_LITE_RUN_LENGTH {
        0 => {
            // An extended (MEGA) run.
            ensure_size!(from: src, size: 1);
            Ok(usize::from(src.read_u8()) + 16)
        }
        run_length => Ok(usize::from(run_length)),
    }
}

fn extract_run_length_mega_mega(src: &mut Buf<'_>) -> Result<usize, RleError> {
    ensure_size!(from: src, size: 2);

    let run_length = usize::from(src.read_u16());

    if run_length == 0 {
        Err(RleError::UnexpectedZeroLength)
    } else {
        Ok(run_length)
    }
}

// TODO: use ironrdp_core::ReadCursor instead
struct Buf<'a> {
    inner: &'a [u8],
    pos: usize,
}

impl<'a> Buf<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { inner: bytes, pos: 0 }
    }

    fn remaining_len(&self) -> usize {
        self.inner.len() - self.pos
    }

    fn read<const N: usize>(&mut self) -> [u8; N] {
        let bytes = &self.inner[self.pos..self.pos + N];
        self.pos += N;
        bytes.try_into().expect("N-elements array")
    }

    fn read_u8(&mut self) -> u8 {
        u8::from_le_bytes(self.read::<1>())
    }

    fn read_u16(&mut self) -> u16 {
        u16::from_le_bytes(self.read::<2>())
    }

    fn read_u24(&mut self) -> u32 {
        let bytes = self.read::<3>();
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0])
    }

    fn rewinded(&'a self, len: usize) -> Buf<'a> {
        Buf {
            inner: self.inner,
            pos: self.pos - len,
        }
    }

    fn eof(&self) -> bool {
        self.pos == self.inner.len()
    }
}

// TODO: use ironrdp_core::WriteCursor instead
struct BufMut<'a> {
    inner: &'a mut [u8],
    pos: usize,
}

impl<'a> BufMut<'a> {
    fn new(bytes: &'a mut [u8]) -> Self {
        Self { inner: bytes, pos: 0 }
    }

    fn remaining_len(&self) -> usize {
        self.inner.len() - self.pos
    }

    fn write(&mut self, bytes: &[u8]) {
        self.inner[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
    }

    fn write_u8(&mut self, value: u8) {
        self.write(&[value]);
    }

    fn write_u16(&mut self, value: u16) {
        self.write(&value.to_le_bytes());
    }

    fn write_u24(&mut self, value: u32) {
        self.write(&value.to_le_bytes()[..3]);
    }

    fn read_pixel_above<Mode: DepthMode>(&self, row_delta: usize) -> Mode::Pixel {
        let read_buf = Buf {
            inner: self.inner,
            pos: self.pos,
        };
        let mut read_buf = read_buf.rewinded(row_delta);
        Mode::read_pixel(&mut read_buf)
    }
}

trait DepthMode {
    type Pixel: Copy + BitXor<Output = Self::Pixel>;

    /// The color depth (in bytes per pixel) for this mode
    const COLOR_DEPTH: usize;

    /// Bits per pixel
    const BPP: usize;

    /// Pixel format for this depth mode
    const PIXEL_FORMAT: RlePixelFormat;

    /// The black pixel value
    const BLACK_PIXEL: Self::Pixel;

    /// The white pixel value
    const WHITE_PIXEL: Self::Pixel;

    /// Writes a pixel to the specified buffer
    fn write_pixel(dst: &mut BufMut<'_>, pixel: Self::Pixel);

    /// Reads a pixel from the specified buffer
    fn read_pixel(src: &mut Buf<'_>) -> Self::Pixel;
}

struct Mode8Bpp;

impl DepthMode for Mode8Bpp {
    type Pixel = u8;

    const COLOR_DEPTH: usize = 1;

    const BPP: usize = 8;

    const PIXEL_FORMAT: RlePixelFormat = RlePixelFormat::Rgb8;

    const BLACK_PIXEL: Self::Pixel = 0x00;

    const WHITE_PIXEL: Self::Pixel = 0xFF;

    fn write_pixel(dst: &mut BufMut<'_>, pixel: Self::Pixel) {
        dst.write_u8(pixel);
    }

    fn read_pixel(src: &mut Buf<'_>) -> Self::Pixel {
        src.read_u8()
    }
}

struct Mode15Bpp;

impl DepthMode for Mode15Bpp {
    type Pixel = u16;

    const COLOR_DEPTH: usize = 2;

    const BPP: usize = 15;

    const PIXEL_FORMAT: RlePixelFormat = RlePixelFormat::Rgb15;

    const BLACK_PIXEL: Self::Pixel = 0x0000;

    // 5 bits per RGB component:
    // 0111 1111 1111 1111 (binary)
    const WHITE_PIXEL: Self::Pixel = 0x7FFF;

    fn write_pixel(dst: &mut BufMut<'_>, pixel: Self::Pixel) {
        dst.write_u16(pixel);
    }

    fn read_pixel(src: &mut Buf<'_>) -> Self::Pixel {
        src.read_u16()
    }
}

struct Mode16Bpp;

impl DepthMode for Mode16Bpp {
    type Pixel = u16;

    const COLOR_DEPTH: usize = 2;

    const BPP: usize = 16;

    const PIXEL_FORMAT: RlePixelFormat = RlePixelFormat::Rgb16;

    const BLACK_PIXEL: Self::Pixel = 0x0000;

    // 5 bits for red, 6 bits for green, 5 bits for green:
    // 1111 1111 1111 1111 (binary)
    const WHITE_PIXEL: Self::Pixel = 0xFFFF;

    fn write_pixel(dst: &mut BufMut<'_>, pixel: Self::Pixel) {
        dst.write_u16(pixel);
    }

    fn read_pixel(src: &mut Buf<'_>) -> Self::Pixel {
        src.read_u16()
    }
}

struct Mode24Bpp;

impl DepthMode for Mode24Bpp {
    type Pixel = u32;

    const COLOR_DEPTH: usize = 3;

    const BPP: usize = 24;

    const PIXEL_FORMAT: RlePixelFormat = RlePixelFormat::Rgb24;

    const BLACK_PIXEL: Self::Pixel = 0x00_0000;

    // 8 bits per RGB component:
    // 1111 1111 1111 1111 1111 1111 (binary)
    const WHITE_PIXEL: Self::Pixel = 0xFF_FFFF;

    fn write_pixel(dst: &mut BufMut<'_>, pixel: Self::Pixel) {
        dst.write_u24(pixel);
    }

    fn read_pixel(src: &mut Buf<'_>) -> Self::Pixel {
        src.read_u24()
    }
}

/// Writes a foreground/background image to a destination buffer.
fn write_fg_bg_image<Mode: DepthMode>(
    dst: &mut BufMut<'_>,
    row_delta: usize,
    bitmask: u8,
    fg_pel: Mode::Pixel,
    mut c_bits: usize,
) -> Result<(), RleError> {
    ensure_size!(into: dst, size: c_bits * Mode::COLOR_DEPTH);

    let mut mask = 0x01;

    repeat::<8>(|| {
        let above_pixel = dst.read_pixel_above::<Mode>(row_delta);

        if bitmask & mask != 0 {
            Mode::write_pixel(dst, above_pixel ^ fg_pel);
        } else {
            Mode::write_pixel(dst, above_pixel);
        }

        c_bits -= 1;
        mask <<= 1;

        c_bits == 0
    });

    Ok(())
}

/// Writes a foreground/background image to a destination buffer
fn write_first_line_fg_bg_image<Mode: DepthMode>(
    dst: &mut BufMut<'_>,
    bitmask: u8,
    fg_pel: Mode::Pixel,
    mut c_bits: usize,
) -> Result<(), RleError> {
    ensure_size!(into: dst, size: c_bits * Mode::COLOR_DEPTH);

    let mut mask = 0x01;

    repeat::<8>(|| {
        if bitmask & mask != 0 {
            Mode::write_pixel(dst, fg_pel);
        } else {
            Mode::write_pixel(dst, Mode::BLACK_PIXEL);
        }

        c_bits -= 1;
        mask <<= 1;

        c_bits == 0
    });

    Ok(())
}

fn repeat<const N: usize>(mut op: impl FnMut() -> bool) {
    for _ in 0..N {
        let stop = op();

        if stop {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! test_buf_mut {
        ($mode:ident) => {{
            let row_delta = 4 * $mode::COLOR_DEPTH;
            let mut buf = vec![0; row_delta * 2];
            let mut dst = BufMut::new(buf.as_mut_slice());

            $mode::write_pixel(&mut dst, 0xDEAD);
            $mode::write_pixel(&mut dst, 0xBEEF);
            $mode::write_pixel(&mut dst, 0xFADE);
            $mode::write_pixel(&mut dst, 0xFEED);

            assert_eq!(dst.read_pixel_above::<$mode>(row_delta), 0xDEAD);
            $mode::write_pixel(&mut dst, $mode::WHITE_PIXEL);
            assert_eq!(dst.read_pixel_above::<$mode>(row_delta), 0xBEEF);
            $mode::write_pixel(&mut dst, $mode::WHITE_PIXEL);
            assert_eq!(dst.read_pixel_above::<$mode>(row_delta), 0xFADE);
            $mode::write_pixel(&mut dst, $mode::WHITE_PIXEL);
            assert_eq!(dst.read_pixel_above::<$mode>(row_delta), 0xFEED);
            $mode::write_pixel(&mut dst, $mode::WHITE_PIXEL);
        }};
    }

    #[test]
    fn buf_mut_16_bpp() {
        test_buf_mut!(Mode16Bpp);
    }

    #[test]
    fn buf_mut_15_bpp() {
        test_buf_mut!(Mode15Bpp);
    }

    #[test]
    fn buf_mut_24_bpp() {
        test_buf_mut!(Mode24Bpp);
    }
}
