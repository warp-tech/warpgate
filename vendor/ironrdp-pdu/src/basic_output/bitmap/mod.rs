#[cfg(test)]
mod tests;

pub mod rdp6;

use core::fmt::{self, Debug};

use bitflags::bitflags;
use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, cast_length, ensure_fixed_part_size,
    ensure_size, invalid_field_err,
};

use crate::geometry::InclusiveRectangle;

const FIRST_ROW_SIZE_VALUE: u16 = 0;

/// TS_UPDATE_BITMAP_DATA
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct BitmapUpdateData<'a> {
    pub rectangles: Vec<BitmapData<'a>>,
}

impl BitmapUpdateData<'_> {
    const NAME: &'static str = "TS_UPDATE_BITMAP_DATA";
    const FIXED_PART_SIZE: usize = 2 /* flags */ + 2 /* nrect */;
}

impl BitmapUpdateData<'_> {
    pub fn encode_header(rectangles: u16, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: 2);

        dst.write_u16(BitmapFlags::BITMAP_UPDATE_TYPE.bits());
        dst.write_u16(rectangles);

        Ok(())
    }
}

impl Encode for BitmapUpdateData<'_> {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        let rectangle_count = cast_length!("number of rectangles", self.rectangles.len())?;

        Self::encode_header(rectangle_count, dst)?;

        for bitmap_data in self.rectangles.iter() {
            bitmap_data.encode(dst)?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        self.rectangles
            .iter()
            .fold(Self::FIXED_PART_SIZE, |size, new| size + new.size())
    }
}

impl<'de> Decode<'de> for BitmapUpdateData<'de> {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let update_type = BitmapFlags::from_bits_retain(src.read_u16());
        if !update_type.contains(BitmapFlags::BITMAP_UPDATE_TYPE) {
            return Err(invalid_field_err!("updateType", "invalid update type"));
        }

        let rectangle_count = usize::from(src.read_u16());
        let mut rectangles = Vec::with_capacity(rectangle_count);

        for _ in 0..rectangle_count {
            rectangles.push(BitmapData::decode(src)?);
        }

        Ok(Self { rectangles })
    }
}

/// TS_BITMAP_DATA
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct BitmapData<'a> {
    pub rectangle: InclusiveRectangle,
    pub width: u16,
    pub height: u16,
    pub bits_per_pixel: u16,
    pub compression_flags: Compression,
    pub compressed_data_header: Option<CompressedDataHeader>,
    pub bitmap_data: &'a [u8],
}

impl BitmapData<'_> {
    const NAME: &'static str = "TS_BITMAP_DATA";
    const FIXED_PART_SIZE: usize = InclusiveRectangle::ENCODED_SIZE + 2 /* width */ + 2 /* height */ + 2 /* bpp */ + 2 /* flags */ + 2 /* len */;

    fn encoded_bitmap_data_length(&self) -> usize {
        self.bitmap_data.len() + self.compressed_data_header.as_ref().map(|hdr| hdr.size()).unwrap_or(0)
    }
}

impl Encode for BitmapData<'_> {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        let encoded_bitmap_data_length = self.encoded_bitmap_data_length();
        let encoded_bitmap_data_length = cast_length!("bitmap data length", encoded_bitmap_data_length)?;

        self.rectangle.encode(dst)?;
        dst.write_u16(self.width);
        dst.write_u16(self.height);
        dst.write_u16(self.bits_per_pixel);
        dst.write_u16(self.compression_flags.bits());
        dst.write_u16(encoded_bitmap_data_length);
        if let Some(compressed_data_header) = &self.compressed_data_header {
            compressed_data_header.encode(dst)?;
        };
        dst.write_slice(self.bitmap_data);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.encoded_bitmap_data_length()
    }
}

impl<'de> Decode<'de> for BitmapData<'de> {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let rectangle = InclusiveRectangle::decode(src)?;
        let width = src.read_u16();
        let height = src.read_u16();
        let bits_per_pixel = src.read_u16();
        let compression_flags = Compression::from_bits_retain(src.read_u16());

        // A 16-bit, unsigned integer. The size in bytes of the data in the bitmapComprHdr
        // and bitmapDataStream fields.
        let encoded_bitmap_data_length = usize::from(src.read_u16());

        ensure_size!(in: src, size: encoded_bitmap_data_length);

        let (compressed_data_header, buffer_length) = if compression_flags.contains(Compression::BITMAP_COMPRESSION)
            && !compression_flags.contains(Compression::NO_BITMAP_COMPRESSION_HDR)
        {
            // Check if encoded_bitmap_data_length is at least CompressedDataHeader::ENCODED_SIZE
            if encoded_bitmap_data_length < CompressedDataHeader::ENCODED_SIZE {
                return Err(invalid_field_err!(
                    "cbCompEncodedBitmapDataLength",
                    "length is less than CompressedDataHeader::ENCODED_SIZE"
                ));
            }

            let buffer_length = encoded_bitmap_data_length - CompressedDataHeader::ENCODED_SIZE;
            (Some(CompressedDataHeader::decode(src)?), buffer_length)
        } else {
            (None, encoded_bitmap_data_length)
        };

        let bitmap_data = src.read_slice(buffer_length);

        Ok(BitmapData {
            rectangle,
            width,
            height,
            bits_per_pixel,
            compression_flags,
            compressed_data_header,
            bitmap_data,
        })
    }
}

impl Debug for BitmapData<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitmapData")
            .field("rectangle", &self.rectangle)
            .field("width", &self.width)
            .field("height", &self.height)
            .field("bits_per_pixel", &self.bits_per_pixel)
            .field("compression_flags", &self.compression_flags)
            .field("compressed_data_header", &self.compressed_data_header)
            .field("bitmap_data.len()", &self.bitmap_data.len())
            .finish()
    }
}

/// TS_CD_HEADER
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct CompressedDataHeader {
    pub main_body_size: u16,
    pub scan_width: u16,
    pub uncompressed_size: u16,
}

impl CompressedDataHeader {
    const NAME: &'static str = "TS_CD_HEADER";
    const FIXED_PART_SIZE: usize = 2 /* row_size */ + 2 /* body_size */ + 2 /* scan_width */ + 2 /* uncompressed_size */;

    pub const ENCODED_SIZE: usize = Self::FIXED_PART_SIZE;
}

impl<'de> Decode<'de> for CompressedDataHeader {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let size = src.read_u16();
        if size != FIRST_ROW_SIZE_VALUE {
            return Err(invalid_field_err!("cbCompFirstRowSize", "invalid first row size"));
        }

        let main_body_size = src.read_u16();
        let scan_width = src.read_u16();

        if !scan_width.is_multiple_of(4) {
            return Err(invalid_field_err!(
                "cbScanWidth",
                "The width of the bitmap must be divisible by 4"
            ));
        }
        let uncompressed_size = src.read_u16();

        Ok(Self {
            main_body_size,
            scan_width,
            uncompressed_size,
        })
    }
}

impl Encode for CompressedDataHeader {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        if !self.scan_width.is_multiple_of(4) {
            return Err(invalid_field_err!(
                "cbScanWidth",
                "The width of the bitmap must be divisible by 4"
            ));
        }
        dst.write_u16(FIRST_ROW_SIZE_VALUE);
        dst.write_u16(self.main_body_size);
        dst.write_u16(self.scan_width);
        dst.write_u16(self.uncompressed_size);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct BitmapFlags: u16{
        const BITMAP_UPDATE_TYPE = 0x0001;

        const _ = !0;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct Compression: u16 {
       const BITMAP_COMPRESSION = 0x0001;
       const NO_BITMAP_COMPRESSION_HDR = 0x0400;

       const _ = !0;
    }
}
