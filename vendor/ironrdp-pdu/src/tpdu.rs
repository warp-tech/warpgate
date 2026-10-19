use ironrdp_core::{
    ReadCursor, WriteCursor, ensure_fixed_part_size, ensure_size, invalid_field_err, read_padding,
    unexpected_message_type_err,
};

use crate::tpkt::TpktHeader;
use crate::{DecodeResult, EncodeResult};

/// TPDU type used during X.224 messages exchange
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TpduCode(u8);

impl TpduCode {
    pub const CONNECTION_REQUEST: Self = Self(0xE0);
    pub const CONNECTION_CONFIRM: Self = Self(0xD0);
    pub const DISCONNECT_REQUEST: Self = Self(0x80);
    pub const DATA: Self = Self(0xF0);
    pub const ERROR: Self = Self(0x70);

    pub fn header_fixed_part_size(self) -> usize {
        if self == TpduCode::DATA {
            TpduHeader::DATA_FIXED_PART_SIZE
        } else {
            TpduHeader::NOT_DATA_FIXED_PART_SIZE
        }
    }

    pub fn check_expected(self, expected: TpduCode) -> DecodeResult<()> {
        if self == expected {
            Ok(())
        } else {
            Err(unexpected_message_type_err!(TpduHeader::NAME, self.0))
        }
    }
}

impl From<u8> for TpduCode {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<TpduCode> for u8 {
    fn from(value: TpduCode) -> Self {
        value.0
    }
}

/// TPDU header, follows a TPKT header
///
/// TPDUs are defined in:
///
/// - <http://www.itu.int/rec/T-REC-X.224-199511-I/> — X.224: Information technology - Open Systems
///   Interconnection - Protocol for providing the connection-mode transport service
/// - RDP uses only TPDUs of class 0, the "simple class" defined in section 8 of X.224
///
/// ```diagram
///       TPDU Header
///  ____________________   byte
/// |                    |
/// |         LI         |   1
/// |____________________|
/// |                    |
/// |        Code        |   2
/// |____________________|
/// |                    |
/// |                    |   3
/// |_______DST-REF______|
/// |                    |
/// |                    |   4
/// |____________________|
/// |                    |
/// |                    |   5
/// |_______SRC-REF______|
/// |                    |
/// |                    |   6
/// |____________________|
/// |                    |
/// |        Class       |   7
/// |____________________|
/// |         ...        |
///```
#[derive(Debug, PartialEq, Eq)]
pub struct TpduHeader {
    /// Length indicator field as defined in section 13.2.1 of X.224.
    ///
    /// The length indicated by LI shall be the header length in octets including
    /// parameters, but excluding the length indicator field and user data, if any.
    ///
    /// ```diagram
    /// ———————————————————————————————————————————————
    /// | LI | Fixed part | Variable part | User data |
    /// |————|————————————|———————————————|———————————|
    /// |    | <—————————— LI ——————————> |           |
    /// | <—————————— Header ———————————> |           |
    /// ```
    pub li: u8,
    /// TPDU code, used to define the structure of the remaining header.
    pub code: TpduCode,
}

impl TpduHeader {
    pub const CONNECTION_REQUEST_FIXED_PART_SIZE: usize = Self::NOT_DATA_FIXED_PART_SIZE;

    pub const CONNECTION_CONFIRM_FIXED_PART_SIZE: usize = Self::NOT_DATA_FIXED_PART_SIZE;

    pub const DISCONNECT_REQUEST_FIXED_PART_SIZE: usize = Self::NOT_DATA_FIXED_PART_SIZE;

    pub const DATA_FIXED_PART_SIZE: usize = 3;

    pub const ERROR_FIXED_PART_SIZE: usize = Self::NOT_DATA_FIXED_PART_SIZE;

    pub const NOT_DATA_FIXED_PART_SIZE: usize = 7;

    pub const NAME: &'static str = "TpduHeader";

    const FIXED_PART_SIZE: usize = Self::DATA_FIXED_PART_SIZE;

    pub fn read(src: &mut ReadCursor<'_>, tpkt: &TpktHeader) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let li = src.read_u8(); // LI
        let code = TpduCode::from(src.read_u8()); // Code

        if usize::from(li) + 1 + TpktHeader::SIZE > usize::from(tpkt.packet_length) {
            return Err(invalid_field_err(
                Self::NAME,
                "li",
                "tpdu length greater than tpkt length",
            ));
        }

        // The value 255 (1111 1111) is reserved for possible extensions.
        if li == 0b1111_1111 {
            return Err(invalid_field_err(
                Self::NAME,
                "li",
                "unsupported X.224 extension (suggested by LI field set to 255)",
            ));
        }

        if code == TpduCode::DATA {
            read_padding!(src, 1); // EOT
        } else {
            ensure_size!(in: src, size: 5);
            read_padding!(src, 5); // DST-REF, SRC-REF, Class 0
        }

        Ok(Self { li, code })
    }

    pub fn write(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        const EOT_BYTE: u8 = 0x80;

        ensure_fixed_part_size!(in: dst);

        dst.write_u8(self.li); // LI
        dst.write_u8(u8::from(self.code)); // Code

        if self.code == TpduCode::DATA {
            dst.write_u8(EOT_BYTE); // EOT
        } else {
            ensure_size!(in: dst, size: 5);
            dst.write_u16(0); // DST-REF
            dst.write_u16(0); // SRC-REF
            dst.write_u8(0); // Class 0
        }

        Ok(())
    }

    /// Fixed part of the TPDU header.
    pub fn fixed_part_size(&self) -> usize {
        self.code.header_fixed_part_size()
    }

    /// Variable part of the TPDU header.
    pub fn variable_part_size(&self) -> usize {
        self.size() - self.fixed_part_size()
    }

    /// Size of the whole TPDU header, including LI field and variable part.
    pub fn size(&self) -> usize {
        usize::from(self.li) + 1
    }
}
