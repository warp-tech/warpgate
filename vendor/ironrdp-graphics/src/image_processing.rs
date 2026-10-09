use core::{cmp, fmt};
use std::io;

use ironrdp_pdu::geometry::{InclusiveRectangle, Rectangle as _};

const ALPHA_OPAQUE: u8 = 0xff;

pub struct ImageRegionMut<'a> {
    pub region: InclusiveRectangle,
    pub step: u16,
    pub pixel_format: PixelFormat,
    pub data: &'a mut [u8],
}

impl fmt::Debug for ImageRegionMut<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImageRegionMut")
            .field("region", &self.region)
            .field("step", &self.step)
            .field("pixel_format", &self.pixel_format)
            .field("data_len", &self.data.len())
            .finish()
    }
}

pub struct ImageRegion<'a> {
    pub region: InclusiveRectangle,
    pub step: u16,
    pub pixel_format: PixelFormat,
    pub data: &'a [u8],
}

impl fmt::Debug for ImageRegion<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImageRegion")
            .field("region", &self.region)
            .field("step", &self.step)
            .field("pixel_format", &self.pixel_format)
            .field("data_len", &self.data.len())
            .finish()
    }
}

impl ImageRegion<'_> {
    pub fn copy_to(&self, other: &mut ImageRegionMut<'_>) -> io::Result<()> {
        let width = cmp::min(self.region.width(), other.region.width());
        let height = cmp::min(self.region.height(), other.region.height());
        let width = usize::from(width);
        let height = usize::from(height);

        let dst_point = Point {
            x: usize::from(other.region.left),
            y: usize::from(other.region.top),
        };
        let src_point = Point {
            x: usize::from(self.region.left),
            y: usize::from(self.region.top),
        };

        let src_byte = usize::from(self.pixel_format.bytes_per_pixel());
        let dst_byte = usize::from(other.pixel_format.bytes_per_pixel());

        let src_step = if self.step == 0 {
            usize::from(self.region.width()) * src_byte
        } else {
            usize::from(self.step)
        };
        let dst_step = if other.step == 0 {
            width * dst_byte
        } else {
            usize::from(other.step)
        };

        if self.pixel_format.eq_no_alpha(other.pixel_format) {
            let width = width * dst_byte;
            for y in 0..height {
                let src_start = (y + src_point.y) * src_step + src_point.x * src_byte;
                let dst_start = (y + dst_point.y) * dst_step + dst_point.x * dst_byte;
                other.data[dst_start..dst_start + width].clone_from_slice(&self.data[src_start..src_start + width]);
            }
        } else {
            for y in 0..height {
                let src = &self.data[((y + src_point.y) * src_step)..];
                let dst = &mut other.data[((y + dst_point.y) * dst_step)..];

                for x in 0..width {
                    let color = self.pixel_format.read_color(&src[((x + src_point.x) * src_byte)..])?;
                    other
                        .pixel_format
                        .write_color(color, &mut dst[((x + dst_point.x) * dst_byte)..])?;
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PixelFormat {
    ARgb32 = 536_971_400,
    XRgb32 = 536_938_632,
    ABgr32 = 537_036_936,
    XBgr32 = 537_004_168,
    BgrA32 = 537_168_008,
    BgrX32 = 537_135_240,
    RgbA32 = 537_102_472,
    RgbX32 = 537_069_704,
}

impl TryFrom<u32> for PixelFormat {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            536_971_400 => Ok(PixelFormat::ARgb32),
            536_938_632 => Ok(PixelFormat::XRgb32),
            537_036_936 => Ok(PixelFormat::ABgr32),
            537_004_168 => Ok(PixelFormat::XBgr32),
            537_168_008 => Ok(PixelFormat::BgrA32),
            537_135_240 => Ok(PixelFormat::BgrX32),
            537_102_472 => Ok(PixelFormat::RgbA32),
            537_069_704 => Ok(PixelFormat::RgbX32),
            _ => Err(()),
        }
    }
}

impl PixelFormat {
    fn as_u32(&self) -> u32 {
        match self {
            Self::ARgb32 => 536_971_400,
            Self::XRgb32 => 536_938_632,
            Self::ABgr32 => 537_036_936,
            Self::XBgr32 => 537_004_168,
            Self::BgrA32 => 537_168_008,
            Self::BgrX32 => 537_135_240,
            Self::RgbA32 => 537_102_472,
            Self::RgbX32 => 537_069_704,
        }
    }

    pub const fn bytes_per_pixel(self) -> u8 {
        match self {
            Self::ARgb32
            | Self::XRgb32
            | Self::ABgr32
            | Self::XBgr32
            | Self::BgrA32
            | Self::BgrX32
            | Self::RgbA32
            | Self::RgbX32 => 4,
        }
    }

    pub fn eq_no_alpha(self, other: Self) -> bool {
        let mask = !(8 << 12);

        (self.as_u32() & mask) == (other.as_u32() & mask)
    }

    /// Returns the byte offsets for the (r, g, b, a) channels within a pixel.
    pub const fn channel_offsets(self) -> [usize; 4] {
        match self {
            Self::ARgb32 | Self::XRgb32 => [1, 2, 3, 0],
            Self::ABgr32 | Self::XBgr32 => [3, 2, 1, 0],
            Self::BgrA32 | Self::BgrX32 => [2, 1, 0, 3],
            Self::RgbA32 | Self::RgbX32 => [0, 1, 2, 3],
        }
    }

    /// Returns `true` if this format carries an alpha channel, `false` for X (padding) formats.
    pub const fn has_alpha(self) -> bool {
        match self {
            Self::ARgb32 | Self::ABgr32 | Self::BgrA32 | Self::RgbA32 => true,
            Self::XRgb32 | Self::XBgr32 | Self::BgrX32 | Self::RgbX32 => false,
        }
    }

    pub fn read_color(self, buffer: &[u8]) -> io::Result<Rgba> {
        if buffer.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "input buffer is not large enough (this is a bug)",
            ));
        }

        let [ri, gi, bi, ai] = self.channel_offsets();
        Ok(Rgba {
            r: buffer[ri],
            g: buffer[gi],
            b: buffer[bi],
            a: if self.has_alpha() { buffer[ai] } else { ALPHA_OPAQUE },
        })
    }

    pub fn write_color(self, color: Rgba, buffer: &mut [u8]) -> io::Result<()> {
        if buffer.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "output buffer is not large enough (this is a bug)",
            ));
        }

        let [ri, gi, bi, ai] = self.channel_offsets();
        buffer[ri] = color.r;
        buffer[gi] = color.g;
        buffer[bi] = color.b;
        buffer[ai] = if self.has_alpha() { color.a } else { ALPHA_OPAQUE };
        Ok(())
    }
}

struct Point {
    x: usize,
    y: usize,
}

pub struct Rgba {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}
