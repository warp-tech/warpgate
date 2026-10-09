use ironrdp_core::{DecodeError, decode};
use ironrdp_pdu::bitmap::rdp6::{BitmapStream as BitmapStreamPdu, ColorPlaneDefinition};

use crate::color_conversion::Rgb;
use crate::rdp6::rle::{RleDecodeError, decompress_8bpp_plane};

#[derive(Debug)]
pub enum BitmapDecodeError {
    Decode(DecodeError),
    Rle(RleDecodeError),
    InvalidUncompressedDataSize,
}

impl core::fmt::Display for BitmapDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BitmapDecodeError::Decode(_error) => write!(f, "failed to decode RDP6 bitmap stream PDU"),
            BitmapDecodeError::Rle(_error) => {
                write!(f, "failed to perform RLE decompression of RDP6 bitmap stream")
            }
            BitmapDecodeError::InvalidUncompressedDataSize => write!(
                f,
                "color plane data size provided in PDU is not sufficient to reconstruct the bitmap"
            ),
        }
    }
}

impl core::error::Error for BitmapDecodeError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            BitmapDecodeError::Decode(err) => Some(err),
            BitmapDecodeError::Rle(err) => Some(err),
            BitmapDecodeError::InvalidUncompressedDataSize => None,
        }
    }
}

impl From<DecodeError> for BitmapDecodeError {
    fn from(err: DecodeError) -> Self {
        BitmapDecodeError::Decode(err)
    }
}

impl From<RleDecodeError> for BitmapDecodeError {
    fn from(err: RleDecodeError) -> Self {
        BitmapDecodeError::Rle(err)
    }
}

/// Implements decoding of RDP6 bitmap stream PDU (see [`BitmapStreamPdu`])
#[derive(Debug, Default)]
pub struct BitmapStreamDecoder {
    /// Optimization to avoid reallocations, re-use this buffer for all bitmaps in the session
    planes_buffer: Vec<u8>,
}

/// Internal implementation of RDP6 bitmap stream PDU decoder for specific image size and format
struct BitmapStreamDecoderImpl<'a> {
    bitmap: BitmapStreamPdu<'a>,
    image_width: usize,
    image_height: usize,
    chroma_width: usize,
    chroma_height: usize,
    full_plane_size: usize,
    chroma_plane_size: usize,
    uncompressed_planes_size: usize,
    color_plane_offsets: [usize; 3],
}

struct AYCoCgParams {
    color_loss_level: u8,
    chroma_subsampling: bool,
    alpha: bool,
}

impl<'a> BitmapStreamDecoderImpl<'a> {
    fn init(bitmap: BitmapStreamPdu<'a>, image_width: usize, image_height: usize) -> Self {
        let (chroma_width, chroma_height) = if bitmap.has_subsampled_chroma() {
            // When image is subsampled, chroma plane has half the size of the luma plane, however
            // its size is rounded up to the nearest greater integer, to take into account odd image
            // size (e.g. if width is 3, then chroma plane width is 2, not 1, to take into account
            // the odd column which expands to 1 pixel instead of 2 during supersampling)
            (image_width.div_ceil(2), image_height.div_ceil(2))
        } else {
            (image_width, image_height)
        };

        let full_plane_size = image_width * image_height;
        let chroma_plane_size = chroma_width * chroma_height;

        let uncompressed_planes_size = if bitmap.has_subsampled_chroma() {
            full_plane_size + chroma_plane_size * 2
        } else {
            full_plane_size * 3
        };

        let color_plane_offsets = [0, full_plane_size, full_plane_size + chroma_plane_size];

        Self {
            bitmap,
            image_width,
            image_height,
            chroma_width,
            chroma_height,
            full_plane_size,
            chroma_plane_size,
            uncompressed_planes_size,
            color_plane_offsets,
        }
    }

    fn decompress_planes(&'a self, aux_buffer: &'a mut Vec<u8>) -> Result<&'a [u8], BitmapDecodeError> {
        let planes = if self.bitmap.header.enable_rle_compression {
            // We don't care for the previous content, just resize it to fit the data
            aux_buffer.resize(self.uncompressed_planes_size, 0);
            let uncompressed_planes_buffer = &mut aux_buffer[..self.uncompressed_planes_size];

            let compressed = self.bitmap.color_panes_data();
            let mut src_offset = 0;

            // Decompress Alpha plane
            if self.bitmap.header.use_alpha {
                // Decompress alpha alpha, but discard it (always 0xFF)
                src_offset += decompress_8bpp_plane(
                    &compressed[src_offset..],
                    uncompressed_planes_buffer,
                    self.image_width,
                    self.image_height,
                )?;
            }

            // Decompress R/Y plane
            src_offset += decompress_8bpp_plane(
                &compressed[src_offset..],
                &mut uncompressed_planes_buffer[self.color_plane_offsets[0]..],
                self.image_width,
                self.image_height,
            )?;

            // Decompress G/Co plane
            src_offset += decompress_8bpp_plane(
                &compressed[src_offset..],
                &mut uncompressed_planes_buffer[self.color_plane_offsets[1]..],
                self.chroma_width,
                self.chroma_height,
            )?;

            // Decompress B/Cg plane
            decompress_8bpp_plane(
                &compressed[src_offset..],
                &mut uncompressed_planes_buffer[self.color_plane_offsets[2]..],
                self.chroma_width,
                self.chroma_height,
            )?;

            &uncompressed_planes_buffer[..self.uncompressed_planes_size]
        } else {
            // Discard alpha plane
            let color_planes_offset = if self.bitmap.header.use_alpha {
                self.full_plane_size
            } else {
                0
            };

            let expected_data_size = color_planes_offset + self.uncompressed_planes_size;

            if self.bitmap.color_panes_data().len() < expected_data_size {
                return Err(BitmapDecodeError::InvalidUncompressedDataSize);
            }

            &self.bitmap.color_panes_data()[color_planes_offset..]
        };

        Ok(planes)
    }

    fn write_argb_planes_to_rgb24(&self, planes: &[u8], dst: &mut Vec<u8>) {
        // For ARGB conversion is simple - just copy data in correct order
        let (r_offset, g_offset, b_offset) = (
            self.color_plane_offsets[0],
            self.color_plane_offsets[1],
            self.color_plane_offsets[2],
        );

        let r_plane = &planes[r_offset..r_offset + self.full_plane_size];
        let g_plane = &planes[g_offset..g_offset + self.full_plane_size];
        let b_plane = &planes[b_offset..b_offset + self.full_plane_size];

        for i in 0..self.full_plane_size {
            let (r, g, b) = (r_plane[i], g_plane[i], b_plane[i]);

            dst.extend_from_slice(&[r, g, b]);
        }
    }

    fn write_aycocg_planes_to_rgb24(&self, params: AYCoCgParams, planes: &[u8], dst: &mut Vec<u8>) {
        #![allow(clippy::similar_names, reason = "it’s hard to find better names for co, cg, etc")]

        let sample_shift = usize::from(params.chroma_subsampling);

        let (y_offset, co_offset, cg_offset) = (
            self.color_plane_offsets[0],
            self.color_plane_offsets[1],
            self.color_plane_offsets[2],
        );

        let y_plane = &planes[y_offset..y_offset + self.full_plane_size];
        let co_plane = &planes[co_offset..co_offset + self.chroma_plane_size];
        let cg_plane = &planes[cg_offset..cg_offset + self.chroma_plane_size];

        for (idx, y) in y_plane.iter().copied().enumerate() {
            let chroma_row = (idx / self.image_width) >> sample_shift;
            let chroma_col = (idx % self.image_width) >> sample_shift;
            let chroma_idx = chroma_row * self.chroma_width + chroma_col;

            let co = co_plane[chroma_idx];
            let cg = cg_plane[chroma_idx];

            let Rgb { r, g, b } = ycocg_with_cll_to_rgb(params.color_loss_level, y, co, cg);

            // As described in 3.1.9.1.2 [MS-RDPEGDI], R and B channels are swapped for
            // AYCoCg when 24-bit image is used (no alpha). We swap them back here
            if params.alpha {
                dst.extend_from_slice(&[r, g, b]);
            } else {
                dst.extend_from_slice(&[b, g, r]);
            }
        }
    }

    fn decode(self, dst: &mut Vec<u8>, aux_buffer: &'a mut Vec<u8>) -> Result<(), BitmapDecodeError> {
        // Reserve enough space for decoded RGB channels data
        dst.reserve(self.image_height * self.image_width * 3);

        match self.bitmap.header.color_plane_definition {
            ColorPlaneDefinition::Argb => {
                let color_planes = self.decompress_planes(aux_buffer)?;
                self.write_argb_planes_to_rgb24(color_planes, dst);
            }
            ColorPlaneDefinition::AYCoCg {
                color_loss_level,
                use_chroma_subsampling,
                ..
            } => {
                let params: AYCoCgParams = AYCoCgParams {
                    color_loss_level,
                    chroma_subsampling: use_chroma_subsampling,
                    alpha: self.bitmap.header.use_alpha,
                };
                let color_planes = self.decompress_planes(aux_buffer)?;
                self.write_aycocg_planes_to_rgb24(params, color_planes, dst);
            }
        }

        Ok(())
    }
}

/// Perform YCoCg -> RGB conversion with color loss reduction (CLL) correction.
fn ycocg_with_cll_to_rgb(cll: u8, y: u8, co: u8, cg: u8) -> Rgb {
    #![allow(clippy::similar_names)] // It’s hard to find better names for co, cg, etc.

    // We decrease CLL by 1 to skip division by 2 for co & cg components during computation of
    // the following color conversion matrix:
    // |R|   |1   1/2   -1/2|   |Y |
    // |G| = |1    0     1/2| * |Co|
    // |B|   |1  -1/2   -1/2|   |Cg|
    let chroma_shift = cll - 1;

    let clip_i16 =
        |v: i16| u8::try_from(v.clamp(0, 255)).expect("fits into u8 because the value is clamped to [0..256]");

    let co_signed = (co << chroma_shift).cast_signed();
    let cg_signed = (cg << chroma_shift).cast_signed();

    let y = i16::from(y);
    let co = i16::from(co_signed);
    let cg = i16::from(cg_signed);

    let t = y - cg;
    let r = clip_i16(t + co);
    let g = clip_i16(y + cg);
    let b = clip_i16(t - co);

    Rgb { r, g, b }
}

impl BitmapStreamDecoder {
    /// Performs decoding of bitmap stream PDU from `bitmap_data` and writes decoded rgb24
    /// image to `dst` buffer.
    pub fn decode_bitmap_stream_to_rgb24(
        &mut self,
        bitmap_data: &[u8],
        dst: &mut Vec<u8>,
        image_width: usize,
        image_height: usize,
    ) -> Result<(), BitmapDecodeError> {
        let bitmap = decode::<BitmapStreamPdu<'_>>(bitmap_data)?;

        let decoder = BitmapStreamDecoderImpl::init(bitmap, image_width, image_height);

        decoder.decode(dst, &mut self.planes_buffer)
    }
}
