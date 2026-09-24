use ironrdp_core::{EncodeError, WriteCursor, not_enough_bytes_err};
use ironrdp_pdu::bitmap::rdp6::{BitmapStreamHeader, ColorPlaneDefinition};

use crate::rdp6::rle::{RleEncodeError, compress_8bpp_plane};

#[derive(Debug)]
pub enum BitmapEncodeError {
    Rle(RleEncodeError),
    Encode(EncodeError),
}

impl core::fmt::Display for BitmapEncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BitmapEncodeError::Rle(_error) => write!(f, "failed to rle compress"),
            BitmapEncodeError::Encode(_error) => write!(f, "failed to encode pdu"),
        }
    }
}

impl core::error::Error for BitmapEncodeError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            BitmapEncodeError::Rle(error) => Some(error),
            BitmapEncodeError::Encode(error) => Some(error),
        }
    }
}

pub trait ColorChannels {
    const STRIDE: usize;
    const R: usize;
    const G: usize;
    const B: usize;
}

pub trait AlphaChannel {
    const A: usize;
}

pub trait PixelFormat {
    const STRIDE: usize;

    fn r(pixel: &[u8]) -> u8;
    fn g(pixel: &[u8]) -> u8;
    fn b(pixel: &[u8]) -> u8;
}

pub trait PixelAlpha: PixelFormat {
    fn a(pixel: &[u8]) -> u8;
}

impl<T> PixelFormat for T
where
    T: ColorChannels,
{
    const STRIDE: usize = T::STRIDE;

    fn r(pixel: &[u8]) -> u8 {
        pixel[T::R]
    }

    fn g(pixel: &[u8]) -> u8 {
        pixel[T::G]
    }

    fn b(pixel: &[u8]) -> u8 {
        pixel[T::B]
    }
}

impl<T> PixelAlpha for T
where
    T: ColorChannels + AlphaChannel,
{
    fn a(pixel: &[u8]) -> u8 {
        pixel[T::A]
    }
}

pub struct RgbChannels;

impl ColorChannels for RgbChannels {
    const STRIDE: usize = 3;
    const R: usize = 0;
    const G: usize = 1;
    const B: usize = 2;
}

pub struct ARgbChannels;

impl ColorChannels for ARgbChannels {
    const STRIDE: usize = 4;
    const R: usize = 1;
    const G: usize = 2;
    const B: usize = 3;
}

impl AlphaChannel for ARgbChannels {
    const A: usize = 0;
}

pub struct RgbAChannels;

impl ColorChannels for RgbAChannels {
    const STRIDE: usize = 4;
    const R: usize = 0;
    const G: usize = 1;
    const B: usize = 2;
}

impl AlphaChannel for RgbAChannels {
    const A: usize = 3;
}

pub struct ABgrChannels;

impl ColorChannels for ABgrChannels {
    const STRIDE: usize = 4;
    const R: usize = 3;
    const G: usize = 2;
    const B: usize = 1;
}

impl AlphaChannel for ABgrChannels {
    const A: usize = 0;
}

pub struct BgrAChannels;

impl ColorChannels for BgrAChannels {
    const STRIDE: usize = 4;
    const R: usize = 2;
    const G: usize = 1;
    const B: usize = 0;
}

impl AlphaChannel for BgrAChannels {
    const A: usize = 3;
}

impl BitmapEncodeError {
    fn rle(e: RleEncodeError) -> Self {
        Self::Rle(e)
    }
}

pub struct BitmapStreamEncoder {
    width: usize,
    height: usize,
}

impl BitmapStreamEncoder {
    pub fn new(width: usize, height: usize) -> Self {
        Self { width, height }
    }

    pub fn encode_channels_stream<R, G, B>(
        &mut self,
        (r, g, b): (R, G, B),
        dst: &mut [u8],
        rle: bool,
    ) -> Result<usize, BitmapEncodeError>
    where
        R: Iterator<Item = u8>,
        G: Iterator<Item = u8>,
        B: Iterator<Item = u8>,
    {
        let mut cursor = WriteCursor::new(dst);

        let header = BitmapStreamHeader {
            enable_rle_compression: rle,
            use_alpha: false,
            color_plane_definition: ColorPlaneDefinition::Argb,
        };

        ironrdp_core::encode_cursor(&header, &mut cursor).map_err(BitmapEncodeError::Encode)?;

        if rle {
            compress_8bpp_plane(r, &mut cursor, self.width, self.height).map_err(BitmapEncodeError::Rle)?;
            compress_8bpp_plane(g, &mut cursor, self.width, self.height).map_err(BitmapEncodeError::Rle)?;
            compress_8bpp_plane(b, &mut cursor, self.width, self.height).map_err(BitmapEncodeError::Rle)?;
        } else {
            let remaining = cursor.len();
            let needed = self.width * self.height * 3 + 1;
            if needed > remaining {
                return Err(BitmapEncodeError::Encode(not_enough_bytes_err(
                    "BitmapStreamData",
                    remaining,
                    needed,
                )));
            }

            for byte in r.chain(g).chain(b) {
                cursor.write_u8(byte);
            }
            cursor.write_u8(0u8);
        }

        Ok(cursor.pos())
    }

    pub fn encode_pixels_stream<'a, I, F>(
        &mut self,
        data: I,
        dst: &mut [u8],
        rle: bool,
    ) -> Result<usize, BitmapEncodeError>
    where
        F: PixelFormat,
        I: Iterator<Item = &'a [u8]> + Clone,
    {
        let r = data.clone().map(F::r);
        let g = data.clone().map(F::g);
        let b = data.map(F::b);

        self.encode_channels_stream((r, g, b), dst, rle)
    }

    pub fn encode_bitmap<F>(&mut self, src: &[u8], dst: &mut [u8], rle: bool) -> Result<usize, BitmapEncodeError>
    where
        F: PixelFormat,
    {
        let r = src.chunks_exact(F::STRIDE).map(F::r);
        let g = src.chunks_exact(F::STRIDE).map(F::g);
        let b = src.chunks_exact(F::STRIDE).map(F::b);

        self.encode_channels_stream((r, g, b), dst, rle)
    }

    pub fn encode_channels_stream_alpha<R, G, B, A>(
        &mut self,
        (r, g, b, a): (R, G, B, A),
        dst: &mut [u8],
        rle: bool,
    ) -> Result<usize, BitmapEncodeError>
    where
        R: Iterator<Item = u8>,
        G: Iterator<Item = u8>,
        B: Iterator<Item = u8>,
        A: Iterator<Item = u8>,
    {
        let mut cursor = WriteCursor::new(dst);

        let header = BitmapStreamHeader {
            enable_rle_compression: rle,
            use_alpha: false,
            color_plane_definition: ColorPlaneDefinition::Argb,
        };

        ironrdp_core::encode_cursor(&header, &mut cursor).map_err(BitmapEncodeError::Encode)?;

        if rle {
            compress_8bpp_plane(a, &mut cursor, self.width, self.height).map_err(BitmapEncodeError::rle)?;
            compress_8bpp_plane(r, &mut cursor, self.width, self.height).map_err(BitmapEncodeError::rle)?;
            compress_8bpp_plane(g, &mut cursor, self.width, self.height).map_err(BitmapEncodeError::rle)?;
            compress_8bpp_plane(b, &mut cursor, self.width, self.height).map_err(BitmapEncodeError::rle)?;
        } else {
            let remaining = cursor.len();
            let needed = self.width * self.height * 4 + 1;
            if needed > remaining {
                return Err(BitmapEncodeError::Encode(not_enough_bytes_err(
                    "BitmapStreamData",
                    remaining,
                    needed,
                )));
            }

            for byte in a.chain(r).chain(g).chain(b) {
                cursor.write_u8(byte);
            }
            cursor.write_u8(0u8);
        }

        Ok(cursor.pos())
    }

    pub fn encode_bitmap_alpha<F>(&mut self, src: &[u8], dst: &mut [u8], rle: bool) -> Result<usize, BitmapEncodeError>
    where
        F: PixelFormat + PixelAlpha,
    {
        let r = src.chunks_exact(F::STRIDE).map(F::r);
        let g = src.chunks_exact(F::STRIDE).map(F::g);
        let b = src.chunks_exact(F::STRIDE).map(F::b);
        let a = src.chunks_exact(F::STRIDE).map(F::a);

        self.encode_channels_stream_alpha((r, g, b, a), dst, rle)
    }
}
