use crate::VncError;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// All supported vnc encodings
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum VncEncoding {
    Raw = 0,
    CopyRect = 1,
    // Rre = 2,
    // Hextile = 5,
    Tight = 7,
    Trle = 15,
    Zrle = 16,
    CursorPseudo = -239,
    DesktopSizePseudo = -223,
    LastRectPseudo = -224,
    ExtendedDesktopSizePseudo = -308,
}

impl From<u32> for VncEncoding {
    fn from(num: u32) -> Self {
        Self::from_wire(num).unwrap_or(Self::Raw)
    }
}

impl VncEncoding {
    pub(crate) fn from_wire(num: u32) -> Result<Self, VncError> {
        match num as i32 {
            0 => Ok(Self::Raw),
            1 => Ok(Self::CopyRect),
            7 => Ok(Self::Tight),
            15 => Ok(Self::Trle),
            16 => Ok(Self::Zrle),
            -239 => Ok(Self::CursorPseudo),
            -223 => Ok(Self::DesktopSizePseudo),
            -224 => Ok(Self::LastRectPseudo),
            -308 => Ok(Self::ExtendedDesktopSizePseudo),
            _ => Err(VncError::InvalidImageData),
        }
    }
}

impl From<VncEncoding> for u32 {
    fn from(e: VncEncoding) -> Self {
        e as u32
    }
}

/// All supported vnc versions
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq)]
#[repr(u8)]
pub enum VncVersion {
    RFB33,
    RFB37,
    RFB38,
}

impl From<[u8; 12]> for VncVersion {
    fn from(version: [u8; 12]) -> Self {
        match &version {
            b"RFB 003.003\n" => VncVersion::RFB33,
            b"RFB 003.007\n" => VncVersion::RFB37,
            b"RFB 003.008\n" => VncVersion::RFB38,
            // https://www.rfc-editor.org/rfc/rfc6143#section-7.1.1
            //  Other version numbers are reported by some servers and clients,
            //  but should be interpreted as 3.3 since they do not implement the
            //  different handshake in 3.7 or 3.8.
            _ => VncVersion::RFB33,
        }
    }
}

impl From<VncVersion> for &[u8; 12] {
    fn from(version: VncVersion) -> Self {
        match version {
            VncVersion::RFB33 => b"RFB 003.003\n",
            VncVersion::RFB37 => b"RFB 003.007\n",
            VncVersion::RFB38 => b"RFB 003.008\n",
        }
    }
}

impl VncVersion {
    /// Read the server's 12-byte version string, returning both the parsed
    /// version and the raw bytes (some servers report non-standard versions).
    pub(crate) async fn read<S>(reader: &mut S) -> Result<(Self, [u8; 12]), VncError>
    where
        S: AsyncRead + Unpin,
    {
        let mut buffer = [0_u8; 12];
        reader.read_exact(&mut buffer).await?;
        Ok((VncVersion::from(buffer), buffer))
    }

    pub(crate) async fn write<S>(self, writer: &mut S) -> Result<(), VncError>
    where
        S: AsyncWrite + Unpin,
    {
        writer
            .write_all(&<VncVersion as Into<&[u8; 12]>>::into(self)[..])
            .await?;
        Ok(())
    }
}

///  Pixel Format Data Structure according to [RFC6143](https://www.rfc-editor.org/rfc/rfc6143.html#section-7.4)
///
/// ```text
/// +--------------+--------------+-----------------+
/// | No. of bytes | Type [Value] | Description     |
/// +--------------+--------------+-----------------+
/// | 1            | U8           | bits-per-pixel  |
/// | 1            | U8           | depth           |
/// | 1            | U8           | big-endian-flag |
/// | 1            | U8           | true-color-flag |
/// | 2            | U16          | red-max         |
/// | 2            | U16          | green-max       |
/// | 2            | U16          | blue-max        |
/// | 1            | U8           | red-shift       |
/// | 1            | U8           | green-shift     |
/// | 1            | U8           | blue-shift      |
/// | 3            |              | padding         |
/// +--------------+--------------+-----------------+
/// ```
#[derive(Debug, Clone, Copy)]
pub struct PixelFormat {
    /// the number of bits used for each pixel value on the wire
    ///
    /// 8, 16, 32(usually) only
    ///
    pub bits_per_pixel: u8,
    /// Although the depth should
    ///
    /// be consistent with the bits-per-pixel and the various -max values,
    ///
    /// clients do not use it when interpreting pixel data.
    ///
    pub depth: u8,
    /// true if multi-byte pixels are interpreted as big endian
    ///
    pub big_endian_flag: u8,
    /// true then the last six items specify how to extract the red, green and blue intensities from the pixel value
    ///
    pub true_color_flag: u8,
    /// the next three always in big-endian order
    /// no matter how the `big_endian_flag` is set
    ///
    pub red_max: u16,
    pub green_max: u16,
    pub blue_max: u16,
    /// the number of shifts needed to get the red value in a pixel to the least significant bit
    ///
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
    _padding_1: u8,
    _padding_2: u8,
    _padding_3: u8,
}

impl From<PixelFormat> for Vec<u8> {
    fn from(pf: PixelFormat) -> Vec<u8> {
        vec![
            pf.bits_per_pixel,
            pf.depth,
            pf.big_endian_flag,
            pf.true_color_flag,
            (pf.red_max >> 8) as u8,
            pf.red_max as u8,
            (pf.green_max >> 8) as u8,
            pf.green_max as u8,
            (pf.blue_max >> 8) as u8,
            pf.blue_max as u8,
            pf.red_shift,
            pf.green_shift,
            pf.blue_shift,
            pf._padding_1,
            pf._padding_2,
            pf._padding_3,
        ]
    }
}

impl TryFrom<[u8; 16]> for PixelFormat {
    type Error = VncError;

    fn try_from(pf: [u8; 16]) -> Result<Self, Self::Error> {
        let bits_per_pixel = pf[0];
        if bits_per_pixel != 8 && bits_per_pixel != 16 && bits_per_pixel != 32 {
            return Err(VncError::WrongPixelFormat);
        }
        let depth = pf[1];
        let big_endian_flag = u8::from(pf[2] != 0);
        let true_color_flag = u8::from(pf[3] != 0);
        let red_max = u16::from_be_bytes(pf[4..6].try_into().unwrap());
        let green_max = u16::from_be_bytes(pf[6..8].try_into().unwrap());
        let blue_max = u16::from_be_bytes(pf[8..10].try_into().unwrap());
        let red_shift = pf[10];
        let green_shift = pf[11];
        let blue_shift = pf[12];
        let _padding_1 = pf[13];
        let _padding_2 = pf[14];
        let _padding_3 = pf[15];
        let format = PixelFormat {
            bits_per_pixel,
            depth,
            big_endian_flag,
            true_color_flag,
            red_max,
            green_max,
            blue_max,
            red_shift,
            green_shift,
            blue_shift,
            _padding_1,
            _padding_2,
            _padding_3,
        };
        format.validate()?;
        Ok(format)
    }
}

impl Default for PixelFormat {
    // by default the pixel transformed is (a << 24 | r << 16 || g << 8 | b) in le
    // which is [b, g, r, a] in network
    fn default() -> Self {
        Self {
            bits_per_pixel: 32,
            depth: 24,
            big_endian_flag: 0,
            true_color_flag: 1,
            red_max: 255,
            green_max: 255,
            blue_max: 255,
            red_shift: 16,
            green_shift: 8,
            blue_shift: 0,
            _padding_1: 0,
            _padding_2: 0,
            _padding_3: 0,
        }
    }
}

impl PixelFormat {
    pub(crate) fn validate(&self) -> Result<(), VncError> {
        if !matches!(self.bits_per_pixel, 8 | 16 | 32)
            || self.depth == 0
            || self.depth > self.bits_per_pixel
            || self.big_endian_flag > 1
            || self.true_color_flag > 1
        {
            return Err(VncError::WrongPixelFormat);
        }
        if self.true_color_flag == 1 {
            let mut mask = 0u64;
            for (max, shift) in [
                (self.red_max, self.red_shift),
                (self.green_max, self.green_shift),
                (self.blue_max, self.blue_shift),
            ] {
                let max = u64::from(max);
                if max == 0 || max & (max + 1) != 0 || shift >= self.bits_per_pixel {
                    return Err(VncError::WrongPixelFormat);
                }
                let component = max << shift;
                if component >= (1u64 << self.bits_per_pixel) || component & mask != 0 {
                    return Err(VncError::WrongPixelFormat);
                }
                mask |= component;
            }
        }
        Ok(())
    }

    // (a << 24 | r << 16 || g << 8 | b) in le
    // [b, g, r, a] in network
    pub fn bgra() -> PixelFormat {
        PixelFormat::default()
    }

    // (a << 24 | b << 16 | g << 8 | r) in le
    // which is [r, g, b, a] in network
    pub fn rgba() -> PixelFormat {
        Self {
            red_shift: 0,
            blue_shift: 16,
            ..Default::default()
        }
    }

    pub(crate) async fn read<S>(reader: &mut S) -> Result<Self, VncError>
    where
        S: AsyncRead + Unpin,
    {
        let mut pixel_buffer = [0_u8; 16];
        reader.read_exact(&mut pixel_buffer).await?;
        pixel_buffer.try_into()
    }
}

#[cfg(test)]
mod tests {
    use super::PixelFormat;

    #[test]
    fn x11vnc_nonzero_wire_flags_are_normalized() {
        let bytes = [32, 24, 0, 255, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0];
        let format = PixelFormat::try_from(bytes).unwrap();
        assert_eq!(format.true_color_flag, 1);
        assert_eq!(format.big_endian_flag, 0);
        assert_eq!(
            (format.red_shift, format.green_shift, format.blue_shift),
            (16, 8, 0)
        );
        let mut big_endian = bytes;
        big_endian[2] = 255;
        assert_eq!(
            PixelFormat::try_from(big_endian).unwrap().big_endian_flag,
            1
        );
        let mut invalid_shift = bytes;
        invalid_shift[10] = 32;
        assert!(PixelFormat::try_from(invalid_shift).is_err());
    }
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    #[test]
    fn true_color_masks_fit_without_overlap() {
        let mut format = PixelFormat::rgba();
        for shift in [8, 32, 255] {
            format.red_shift = shift;
            assert!(format.validate().is_err());
        }
        format = PixelFormat::rgba();
        for max in [0, 254, u16::MAX] {
            format.red_max = max;
            assert!(format.validate().is_err());
        }
        format = PixelFormat::rgba();
        format.bits_per_pixel = 16;
        format.depth = 16;
        format.red_max = 31;
        format.green_max = 63;
        format.blue_max = 31;
        format.red_shift = 11;
        format.green_shift = 5;
        format.blue_shift = 0;
        assert!(format.validate().is_ok());
        format.bits_per_pixel = 8;
        format.depth = 8;
        format.red_max = 7;
        format.green_max = 7;
        format.blue_max = 3;
        format.red_shift = 5;
        format.green_shift = 2;
        assert!(format.validate().is_ok());
    }
}
